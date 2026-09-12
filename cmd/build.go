package cmd

import (
	"fmt"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"bomify/internal/build"
	"bomify/internal/logging"
	"bomify/internal/plugin"
)

type buildOptions struct {
	file        string
	output      string
	clean       bool
	hash        string
	concurrency int
	tags        []string
}

// buildCmd builds the `bomify build` command.
func buildCmd() *cobra.Command {

	buildOpts := &buildOptions{}

	buildCmd := &cobra.Command{
		Use:   "build <sbom-file>",
		Short: "Build builds the package described by a CycloneDX SBOM",
		Long:  "Build reads a CycloneDX SBOM and builds a containing each component it describes.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			buildOpts.file = args[0]
			if err := runBuild(buildOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("build: %w", err)
			}
			return nil
		},
	}

	buildCmd.Flags().StringVarP(&buildOpts.output, "output", "o", "dist", "directory to write components to")
	buildCmd.Flags().BoolVar(&buildOpts.clean, "clean", false, "remove the output directory before building")
	buildCmd.Flags().StringVar(&buildOpts.hash, "hash", "sha-256", "hash algorithm to verify pulled components against their SBOM-declared hash")
	buildCmd.Flags().IntVarP(&buildOpts.concurrency, "concurrency", "c", 1, "number of components to pull concurrently")
	buildCmd.Flags().StringArrayVarP(&buildOpts.tags, "tag", "t", nil, "tag this build as name[:version] (repeatable); defaults version to \"latest\"")

	return buildCmd
}

func runBuild(opts *buildOptions, logger *slog.Logger) error {
	hashAlgorithm, err := plugin.NormalizeHashAlgorithm(opts.hash)
	if err != nil {
		return err
	}

	if opts.clean {
		logger.Info("cleaning output directory", "path", opts.output)
		if err := os.RemoveAll(opts.output); err != nil {
			return fmt.Errorf("clean output directory %s: %w", opts.output, err)
		}
	}

	if err := forEachComponent(opts.file, logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path)

		result, err := plugin.Pull(path, component, opts.output, hashAlgorithm)
		if err != nil {
			return err
		}

		log.Info("pull complete", "output", result.OutputPath, "message", result.Message, "hash", result.Hash.Value)

		return nil
	}); err != nil {
		return err
	}

	return finalizeBuild(opts, logger)
}

// finalizeBuild runs once every component in the SBOM has been pulled
// successfully: it records the SBOM itself as this build's manifest
// (keyed by the SBOM file's own content hash), skipping that specifically
// if that exact SBOM has already been built. Either way, it still maps
// any --tag values onto the manifest's hash: a tag is bookkeeping about
// this invocation's request, not about the manifest, so it's applied even
// when the manifest itself already existed.
func finalizeBuild(opts *buildOptions, logger *slog.Logger) error {
	sbomHash, skipped, err := build.RecordManifest(opts.output, opts.file)
	if err != nil {
		return fmt.Errorf("record sbom manifest: %w", err)
	}
	if skipped {
		logger.Info("sbom already built, skipping", "hash", sbomHash)
	} else {
		logger.Info("sbom build manifest written", "hash", sbomHash)
	}

	if err := build.UpdateRepositories(opts.output, opts.tags, sbomHash); err != nil {
		return fmt.Errorf("update repositories: %w", err)
	}
	if len(opts.tags) > 0 {
		logger.Info("tagged", "tags", opts.tags, "hash", sbomHash)
	}

	return nil
}
