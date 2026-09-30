package cmd

import (
	"fmt"
	"log/slog"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/plugin/install"
	"github.com/alejandro-velasco/bomify/internal/provenance"
)

const buildShort = "Build the package described by a CycloneDX SBOM"

const buildLong = `Build pulls every component a CycloneDX SBOM describes, each through
the plugin for its purl type, and records the SBOM as the build so
push, distribute, tag, and packages can find it.

A "pkg:bomify-plugin/..." component is a plugin binary: bomify copies it
from the path or file:// URL in its "distribution" external reference
(relative to the SBOM). Packages built this way are what "bomify plugin
install" installs.

--check asks each plugin to confirm its component is reachable and
authorized, without downloading anything or recording a build.

--provenance records SLSA provenance of the build: the SBOM, every
component and plugin binary by digest, and bomify's version. "bomify
push" and "bomify save" attach it as an in-toto attestation, signed with
--sign, for tools like cosign and slsa-verifier to check.`

const buildExample = `  # Build the package described by sbom.json
  bomify build sbom.json

  # Build and tag the result as myapp:latest
  bomify build sbom.json --tag myapp:latest

  # Pull up to 4 components concurrently
  bomify build sbom.json --concurrency 4

  # Verify every component is pullable, without downloading anything
  bomify build sbom.json --check

  # Record SLSA provenance, attached when the package is pushed
  bomify build sbom.json --tag myapp:1.0 --provenance`

type buildOptions struct {
	file        string
	concurrency int
	tags        []string
	check       bool
	provenance  bool
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

	buildCmd.Flags().IntVarP(&buildOpts.concurrency, "concurrency", "c", 1, "number of components to pull concurrently")
	buildCmd.Flags().StringArrayVarP(&buildOpts.tags, "tag", "t", nil, "tag this build as name[:version] (repeatable); defaults version to \"latest\"")
	buildCmd.Flags().BoolVar(&buildOpts.check, "check", false, "verify every component is pullable and authorized, without downloading any of them or recording a build")
	buildCmd.Flags().BoolVar(&buildOpts.provenance, "provenance", false, "record SLSA provenance of this build, attached when the package is pushed or saved")
	buildCmd.MarkFlagsMutuallyExclusive("check", "provenance")

	return buildCmd
}

func runBuild(opts *buildOptions, logger *slog.Logger) error {
	var (
		rec       *provenance.Recorder
		installed map[string]*install.Record
	)
	if opts.provenance {
		rec = provenance.NewRecorder()
		entries, err := install.List(dataDir)
		if err != nil {
			return err
		}
		installed = map[string]*install.Record{}
		for _, e := range entries {
			installed[e.Kind] = e.Record
		}
	}

	if err := forEachComponent(opts.file, logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		if _, isBinary, err := plugin.ParseBinary(component); err != nil {
			return err
		} else if isBinary {
			return buildPluginBinary(opts, component, rec, log)
		}

		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path)

		if opts.check {
			result, err := plugin.CheckPull(path, component, dataDir, log)
			if err != nil {
				return err
			}
			log.Info("check complete", "output", result.OutputPath, "message", result.Message, "hash", result.Hash.Value)
			return nil
		}

		result, err := plugin.Pull(path, component, dataDir, log)
		if err != nil {
			return err
		}
		if rec != nil {
			rec.AddComponent(component.PackageURL, result.Hash.Value)
			var version, sum string
			if r := installed[kind]; r != nil {
				version, sum = r.Version, r.SHA256
			}
			if err := rec.AddPlugin(kind, path, version, sum, plugin.HashFile); err != nil {
				return err
			}
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

	sbomHash, err := finalizeBuild(opts, logger)
	if err != nil {
		return err
	}
	if rec != nil {
		if err := rec.Write(dataDir, sbomHash, opts.tags); err != nil {
			return fmt.Errorf("record provenance: %w", err)
		}
		logger.Info("provenance recorded", "hash", sbomHash)
	}
	return nil
}

// buildPluginBinary builds a plugin.PurlType component: bomify copies the
// plugin binary its "distribution" external reference names itself,
// rather than delegating to a plugin (see plugin.PullBinary).
func buildPluginBinary(opts *buildOptions, component cdx.Component, rec *provenance.Recorder, log *slog.Logger) error {
	sbomDir := filepath.Dir(opts.file)

	if opts.check {
		result, err := plugin.CheckBinary(component, sbomDir)
		if err != nil {
			return err
		}
		log.Info("check complete", "message", result.Message, "hash", result.Hash.Value)
		return nil
	}

	result, err := plugin.PullBinary(component, sbomDir, dataDir)
	if err != nil {
		return err
	}

	log.Info("plugin binary added", "output", result.OutputPath, "message", result.Message, "hash", result.Hash.Value)
	if rec != nil {
		rec.AddComponent(component.PackageURL, result.Hash.Value)
	}
	return nil
}

// finalizeBuild records the SBOM as this build's manifest and applies any
// --tag values, even if that exact manifest already existed, returning
// the SBOM's hash.
func finalizeBuild(opts *buildOptions, logger *slog.Logger) (string, error) {
	sbomHash, skipped, err := build.RecordManifest(dataDir, opts.file)
	if err != nil {
		return "", fmt.Errorf("record sbom manifest: %w", err)
	}
	if skipped {
		logger.Info("sbom already built, skipping", "hash", sbomHash)
	} else {
		logger.Info("sbom build manifest written", "hash", sbomHash)
	}

	if err := build.UpdateRepositories(dataDir, opts.tags, sbomHash); err != nil {
		return "", fmt.Errorf("update repositories: %w", err)
	}
	if len(opts.tags) > 0 {
		logger.Info("tagged", "tags", opts.tags, "hash", sbomHash)
	}

	return sbomHash, nil
}
