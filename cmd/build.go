package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

const buildShort = "Build the package described by a CycloneDX SBOM"

const buildLong = `Build reads a CycloneDX SBOM and builds a package containing each
component it describes. Each component is resolved to a plugin by its
kind and pulled through it, and the SBOM is then recorded as this
build's manifest so later commands (push, distribute, tag, packages)
can find it.

--check verifies every component is pullable and authorized — an
inexpensive existence/auth check each plugin performs itself, without
downloading anything — and skips recording a build, since nothing was
actually pulled.`

const buildExample = `  # Build the package described by sbom.json
  bomify build sbom.json

  # Build and tag the result as myapp:latest
  bomify build sbom.json --tag myapp:latest

  # Pull up to 4 components concurrently, verifying against sha-512
  bomify build sbom.json --concurrency 4 --hash sha-512

  # Verify every component is pullable, without downloading anything
  bomify build sbom.json --check`

type buildOptions struct {
	file        string
	hash        string
	concurrency int
	tags        []string
	check       bool
}

func buildCmd() *cobra.Command {

	buildOpts := &buildOptions{}

	buildCmd := &cobra.Command{
		Use:     "build <sbom-file>",
		Short:   buildShort,
		Long:    buildLong,
		Example: buildExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			buildOpts.file = args[0]
			if err := runBuild(buildOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("build: %w", err)
			}
			return nil
		},
	}

	buildCmd.Flags().StringVar(&buildOpts.hash, "hash", "sha-256", "hash algorithm to verify pulled components against their SBOM-declared hash")
	buildCmd.Flags().IntVarP(&buildOpts.concurrency, "concurrency", "c", 1, "number of components to pull concurrently")
	buildCmd.Flags().StringArrayVarP(&buildOpts.tags, "tag", "t", nil, "tag this build as name[:version] (repeatable); defaults version to \"latest\"")
	buildCmd.Flags().BoolVar(&buildOpts.check, "check", false, "verify every component is pullable and authorized, without downloading any of them or recording a build")

	return buildCmd
}

func runBuild(opts *buildOptions, logger *slog.Logger) error {
	hashAlgorithm, err := plugin.NormalizeHashAlgorithm(opts.hash)
	if err != nil {
		return err
	}

	if err := forEachComponent(opts.file, logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path)

		if opts.check {
			result, err := plugin.CheckPull(path, component, dataDir, hashAlgorithm, log)
			if err != nil {
				return err
			}
			log.Info("check complete", "output", result.OutputPath, "message", result.Message, "hash", result.Hash.Value)
			return nil
		}

		result, err := plugin.Pull(path, component, dataDir, hashAlgorithm, log)
		if err != nil {
			return err
		}

		log.Info("pull complete", "output", result.OutputPath, "message", result.Message, "hash", result.Hash.Value)

		return nil
	}); err != nil {
		return err
	}

	if opts.check {
		// Nothing was actually pulled, so there's no build to record.
		return nil
	}

	return finalizeBuild(opts, logger)
}

// finalizeBuild records the SBOM as this build's manifest and applies any
// --tag values, even if that exact manifest already existed.
func finalizeBuild(opts *buildOptions, logger *slog.Logger) error {
	sbomHash, skipped, err := build.RecordManifest(dataDir, opts.file)
	if err != nil {
		return fmt.Errorf("record sbom manifest: %w", err)
	}
	if skipped {
		logger.Info("sbom already built, skipping", "hash", sbomHash)
	} else {
		logger.Info("sbom build manifest written", "hash", sbomHash)
	}

	if err := build.UpdateRepositories(dataDir, opts.tags, sbomHash); err != nil {
		return fmt.Errorf("update repositories: %w", err)
	}
	if len(opts.tags) > 0 {
		logger.Info("tagged", "tags", opts.tags, "hash", sbomHash)
	}

	return nil
}
