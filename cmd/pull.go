package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
)

const pullShort = "Download a bomify package from an OCI registry"

const pullLong = `Pull downloads a bomify package artifact from an OCI registry: its
config (the aggregate SBOM manifest) and each of its layers (the
components that SBOM describes), laying them out in the data
directory exactly as "bomify build" would have. Layers download
concurrently, each with its own progress bar.`

const pullExample = `  # Pull a tagged reference
  bomify pull registry.example.com/myapp:latest

  # Pull by digest
  bomify pull registry.example.com/myapp@sha256:abcdef...

  # Download up to 6 layers concurrently
  bomify pull registry.example.com/myapp:latest --concurrency 6`

type pullOptions struct {
	concurrency int
}

func pullCmd() *cobra.Command {
	opts := &pullOptions{}

	cmd := &cobra.Command{
		Use:     "pull <reference>",
		Short:   pullShort,
		Long:    pullLong,
		Example: pullExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPull(cmd, args[0], opts); err != nil {
				return fmt.Errorf("pull: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 3, "number of layers to download concurrently")

	return cmd
}

func runPull(cmd *cobra.Command, ref string, opts *pullOptions) error {
	logger := logging.FromContext(cmd.Context())

	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	mb := newMultiBar(cmd.OutOrStderr())
	progress := newProgressFunc(mb)

	result, err := pull.Pull(cmd.Context(), repo, ref, dataDir, opts.concurrency, progress)
	mb.Wait()
	if err != nil {
		return err
	}

	logPulledLayers(logger, result)

	// Record ref as a local tag, unless it's a digest reference
	// (repo@sha256:...), which would mis-split on its own colon.
	if parsed, err := registry.ParseReference(ref); err == nil && parsed.ValidateReferenceAsTag() == nil {
		if err := build.UpdateRepositories(dataDir, []string{ref}, result.SBOMHash); err != nil {
			return fmt.Errorf("update repositories: %w", err)
		}
		logger.Info("tagged", "tags", []string{ref}, "hash", result.SBOMHash)
	} else {
		logger.Debug("pulled by digest, not recording a tag", "ref", ref)
	}

	return nil
}

func logPulledLayers(logger *slog.Logger, result pull.Result) {
	logger.Info("sbom manifest restored", "hash", result.SBOMHash)
	for _, layer := range result.Layers {
		logger.Info("layer restored", "purl", layer.Purl, "hash", layer.Hash, "path", layer.Path)
	}
}
