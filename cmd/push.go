package cmd

import (
	"context"
	"fmt"
	"log/slog"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	"github.com/alejandro-velasco/bomify/internal/security"
)

const pushShort = "Publish a bomify package to an OCI registry"

const pushLong = `Push packages the SBOM manifest a prior "bomify build" recorded for
<tag> (and each component it describes) as an OCI artifact, and
publishes it under <tag>. <tag> is both the local bookkeeping key
(see "bomify tag" / "bomify packages") and the destination reference.

Every local vulnerability report from a prior "bomify security scan" of
the package's components is attached to it as a single OCI referrer,
rather than as part of the package itself: re-scanning and pushing
again leaves the package's digest, and so any signature over it,
unchanged, and just attaches a newer report referrer. Pushing again
with unchanged reports attaches nothing new. Once attached, all but the
newest --keep-reports report referrers (default 1; 0 keeps them all)
are deleted from the registry, each with its own signature. Deletion
is best-effort: a registry that refuses it (e.g. ghcr.io) only logs a
warning, and "bomify security prune" can retry it later.

--sign signs the pushed package with a signing plugin before <tag> is
updated to point at it, attaching the signature to it as an OCI
referrer. One signature covers the SBOM and every component; the
report referrer is signed separately, the same way. See "bomify pull
--verify" and "bomify trust" for checking them.

--scan <type> scans the package's components fresh before anything is
uploaded — the reports it writes are the ones the package then carries
— and --fail-on <severity> (with --ignore and --vex) refuses to push it
if anything at or above it is found. --fail-on without --scan gates on
the reports a prior scan left instead. A "bomify security policy" rule
listing "push" in its --on does the same for a matching <tag> without
flags; --skip-scan ignores it.

--quiet prints only the pushed package's pinned reference,
<repository>@<digest>, on stdout — no progress bars, and no logging but
warnings and errors — for scripts that go on to publish or pin it.`

const pushExample = `  # Push the package tagged myapp:latest to its own registry reference
  bomify push myapp:latest

  # Push using a fully qualified registry reference as the tag
  bomify push registry.example.com/myapp:latest

  # Upload up to 6 layers concurrently
  bomify push myapp:latest --concurrency 6

  # Sign the package with a cosign key while pushing it
  bomify push registry.example.com/myapp:latest --sign sigstore --sign-option key=cosign.key

  # Print just the pinned reference, e.g. to publish it
  pinned=$(bomify push registry.example.com/myapp:latest --quiet)`

type pushOptions struct {
	concurrency int
	keepReports int
	sign        signFlags
	scan        scanFlags
	quiet       bool
}

func pushCmd() *cobra.Command {
	opts := &pushOptions{}

	cmd := &cobra.Command{
		Use:     "push <tag>",
		Short:   pushShort,
		Long:    pushLong,
		Example: pushExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPush(cmd, args[0], opts); err != nil {
				return fmt.Errorf("push: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 3, "number of layers to upload concurrently")
	cmd.Flags().BoolVarP(&opts.quiet, "quiet", "q", false, "print only the pushed package's pinned reference (<repository>@<digest>), with no progress or informational logging")
	cmd.Flags().IntVar(&opts.keepReports, "keep-reports", 1, "number of newest vulnerability report referrers to keep on the registry after pushing; older ones are deleted (0 keeps them all)")
	opts.sign.register(cmd)
	opts.scan.register(cmd)

	return cmd
}

func runPush(cmd *cobra.Command, tag string, opts *pushOptions) error {
	logger := logging.FromContext(cmd.Context())
	if opts.quiet {
		logger = logging.WarningsOnly(logger)
	}

	sbomHash, err := build.ResolveTag(dataDir, tag)
	if err != nil {
		return err
	}

	signer, err := opts.sign.signer(logger)
	if err != nil {
		return err
	}

	// Gated before anything is uploaded; fresh reports are what the
	// pushed package then carries.
	p, err := opts.scan.plan(tag, security.HookPush, logger)
	if err != nil {
		return err
	}
	if p.active() {
		if err := gateLocalPackage(cmd.ErrOrStderr(), p, sbomHash, opts.concurrency, logger); err != nil {
			return fmt.Errorf("not pushed: %w", err)
		}
	}

	repo, err := newRepository(tag)
	if err != nil {
		return err
	}

	var progress transfer.ProgressFunc
	if !opts.quiet {
		mb := newMultiBar(cmd.OutOrStderr())
		defer mb.Wait()
		progress = newProgressFunc(mb)
	}

	result, err := push.Push(cmd.Context(), repo, tag, dataDir, sbomHash, opts.concurrency, progress, transfer.Hooks{Sign: signer})
	if err != nil {
		return err
	}

	logPushedLayers(logger, result)
	pruneReports(cmd.Context(), logger, repo, result.Manifest, opts.keepReports)

	if opts.quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "%s@%s\n", prefix.Repository(tag), result.ManifestDigest)
	}
	return nil
}

// pruneReports deletes all but the newest keep vulnerability report
// referrers of manifest from repo (see security.PruneReferrers), logging
// rather than failing on anything it couldn't delete.
func pruneReports(ctx context.Context, logger *slog.Logger, repo security.PruneTarget, manifest ocispec.Descriptor, keep int) {
	deleted, err := security.PruneReferrers(ctx, repo, manifest, keep)
	for _, d := range deleted {
		logger.Info("stale referrer deleted", "digest", d.Digest.String(), "artifactType", d.ArtifactType)
	}
	if err != nil {
		logger.Warn("could not delete stale vulnerability reports; retry with \"bomify security prune\"", "error", err)
	}
}

func logPushedLayers(logger *slog.Logger, result push.Result) {
	logger.Info("manifest pushed", "digest", result.ManifestDigest)
	for _, layer := range result.Layers {
		logger.Info("layer pushed", "purl", layer.Purl, "hash", layer.Hash)
	}
	for _, report := range result.VulnerabilityReports {
		logger.Info("vulnerability report attached", "purl", report.Purl, "hash", report.Hash)
	}
	if len(result.VulnerabilityReports) > 0 {
		logger.Info("vulnerability reports referrer attached", "digest", result.ReportsReferrer.Digest.String())
	}
}
