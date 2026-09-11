package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/alejandro-velasco/bomify/internal/auth"
	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
)

type pullOptions struct {
	concurrency int
}

func pullCmd() *cobra.Command {
	opts := &pullOptions{}

	cmd := &cobra.Command{
		Use:   "pull <reference>",
		Short: "Pull downloads a bomify package from an OCI registry",
		Long:  "Pull downloads a bomify package artifact from an OCI registry: its config (the aggregate SBOM manifest) and each of its layers (the components that SBOM describes), laying them out in the data directory exactly as `bomify build` would have. Layers download concurrently, each with its own progress bar.",
		Args:  cobra.ExactArgs(1),
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
	if err != nil {
		return err
	}

	logPulledLayers(logger, result)

	// ref is both the OCI reference just pulled from and, like `bomify
	// push`'s <tag>, the natural local bookkeeping key for it: record it
	// in repositories.json so `bomify packages`/`tag`/`push` all see this
	// pull as a known local package. Only do this when ref is actually a
	// tag, though: a digest reference (repo@sha256:...) fed through the
	// same repo:version split `bomify build -t`/`bomify tag` use would be
	// mis-split on the digest's own colon.
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

// newRepository builds a remote.Repository for ref, authenticating with
// whatever credentials `bomify login` (or `docker login` — they share a
// store) has for its registry. A registry with no stored credentials is
// accessed anonymously.
func newRepository(ref string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %s: %w", ref, err)
	}

	client, err := auth.Client()
	if err != nil {
		return nil, err
	}
	repo.Client = client

	return repo, nil
}
