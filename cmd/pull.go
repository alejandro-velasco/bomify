package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
)

const pullShort = "Download a bomify package from an OCI registry"

const pullLong = `Pull downloads a package from an OCI registry into the data directory,
as if it had been built there, along with the newest vulnerability
reports attached to it. Reports are advisory: if they can't be fetched
or verified, the package is still restored, with a warning.

--verify requires a signature the named plugin verifies; without it, a
matching "bomify trust" rule applies. The package is verified before
anything is written. --insecure-skip-verify bypasses a trust rule.

--scan <type> --fail-on <severity> scans the package fresh, after
verification and before anything is written, and refuses it if anything
is at or above <severity>. The two go together. A matching "bomify
security policy" rule with --on pull does the same without flags, and
its stored VEX exempts what it covers; flags override the rule, and
--skip-scan ignores it. VEX the publisher attached (see "bomify push
--vex") also counts, but only when this pull verifies signatures and
each document's own signature verifies. Scanning may need network
access.

--quiet prints only the package's pinned reference,
<repository>@<digest>, with no progress or info logging.`

const pullExample = `  # Pull a tagged reference
  bomify pull registry.example.com/myapp:latest

  # Pull by digest
  bomify pull registry.example.com/myapp@sha256:abcdef...

  # Download up to 6 layers concurrently
  bomify pull registry.example.com/myapp:latest --concurrency 6

  # Require a signature made with a specific cosign key
  bomify pull registry.example.com/myapp:latest --verify sigstore --verify-option key=cosign.pub

  # Print just the pinned reference of what was pulled
  pinned=$(bomify pull registry.example.com/myapp:latest --quiet)`

type pullOptions struct {
	restoreFlags
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

	opts.register(cmd, "download", "print only the restored package's pinned reference (<repository>@<digest>), with no progress or informational logging")

	return cmd
}

func runPull(cmd *cobra.Command, ref string, opts *pullOptions) error {
	r, err := opts.start(cmd)
	if err != nil {
		return err
	}
	logger := r.logger

	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	result, err := pull.Pull(cmd.Context(), repo, ref, dataDir, r.opts)
	if err != nil {
		r.done()
		return err
	}
	if err := r.finish(); err != nil {
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

	opts.printPinned(cmd, ref, result.ManifestDigest)
	return nil
}

func logPulledLayers(logger *slog.Logger, result pull.Result) {
	logger.Info("sbom manifest restored", "hash", result.SBOMHash)
	for _, layer := range result.Layers {
		logger.Info("layer restored", "purl", layer.Purl, "hash", layer.Hash, "path", layer.Path)
	}
	for _, report := range result.VulnerabilityReports {
		logger.Info("vulnerability report restored", "purl", report.Purl, "hash", report.Hash, "path", report.Path)
	}
	if result.ReportsSkipped != nil {
		logger.Warn("vulnerability reports not restored", "error", result.ReportsSkipped)
	}
}
