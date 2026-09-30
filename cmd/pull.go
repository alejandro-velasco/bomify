package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
)

const pullShort = "Download a bomify package from an OCI registry"

const pullLong = `Pull downloads a bomify package artifact from an OCI registry: its
config (the aggregate SBOM manifest) and each of its layers (the
components that SBOM describes), laying them out in the data
directory exactly as "bomify build" would have. Layers download
concurrently, each with its own progress bar.

The vulnerability reports of the package's newest report referrer (see
"bomify push") are restored to
"<data-dir>/vulnerabilities/<purl-hash>.json", the same path "bomify
security scan" itself would have written them to. Reports are
advisory: if they can't be listed, fetched, or verified, the package is
still restored, and a warning says why its reports weren't.

--verify requires the package to carry a signature the named signing
plugin verifies (see "bomify push --sign"); without it, any "bomify
trust" rule matching <reference> applies instead. Either way, the
signature is checked before anything is written to the data
directory, so a package that fails verification leaves no trace. The
report referrer's own signature is checked the same way before its
reports are restored.
--insecure-skip-verify bypasses a matching trust rule.

--scan <type> --fail-on <severity> scans the package's components
fresh — after --verify, before anything is written — and refuses to
restore it if anything at or above <severity> is found, leaving no
trace, as a failed verify does; a matching rule's stored VEX documents
exempt what they cover. The fresh reports replace the ones the package
carries. The two go together: --fail-on without --scan would gate on
the publisher's own reports, and --scan without a threshold couldn't
refuse anything (to just scan, run "bomify security scan" after
pulling). A "bomify security policy" rule listing "pull" in its --on
does the same for a matching <reference> without flags, and either
flag overrides its part of the rule; --skip-scan ignores it. VEX
documents the package's publisher attached (see "bomify push --vex")
also exempt what they cover — but only when this pull verifies
signatures and each document's own signature verifies; otherwise
they're ignored with a warning. Scanning
may need network access (e.g. grype's database, or the images it
scans).

--quiet prints only the restored package's pinned reference,
<repository>@<digest>, on stdout — no progress bars, and no logging but
warnings and errors.`

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
	concurrency int
	verify      verifyFlags
	scan        scanFlags
	quiet       bool
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
	cmd.Flags().BoolVarP(&opts.quiet, "quiet", "q", false, "print only the restored package's pinned reference (<repository>@<digest>), with no progress or informational logging")
	opts.verify.register(cmd)
	opts.scan.register(cmd)

	return cmd
}

func runPull(cmd *cobra.Command, ref string, opts *pullOptions) error {
	logger := logging.FromContext(cmd.Context())
	if opts.quiet {
		logger = logging.WarningsOnly(logger)
	}

	verifier, policy, err := opts.verify.verifier(dataDir, logger)
	if err != nil {
		return err
	}
	if err := opts.scan.validate(); err != nil {
		return err
	}
	scanHook := &pullScanHook{flags: &opts.scan, w: cmd.ErrOrStderr(), concurrency: opts.concurrency, logger: logger, policy: policy, verify: verifier}

	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	var progress pull.ProgressFunc
	if !opts.quiet {
		mb := newMultiBar(cmd.OutOrStderr())
		defer mb.Wait()
		progress = newProgressFunc(mb)
	}

	result, err := pull.Pull(cmd.Context(), repo, ref, dataDir, opts.concurrency, progress, transfer.Hooks{Verify: verifier, Scan: scanHook.scan})
	if err != nil {
		return err
	}
	// Written after the package's own reports, so a fresh scan replaces
	// what the publisher attached.
	if err := writeReports(scanHook.collected); err != nil {
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

	if opts.quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "%s@%s\n", prefix.Repository(ref), result.ManifestDigest)
	}
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
