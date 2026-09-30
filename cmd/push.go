package cmd

import (
	"context"
	"fmt"
	"log/slog"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/security"
)

const pushShort = "Publish a bomify package to an OCI registry"

const pushLong = `Push publishes the local package <tag> as an OCI artifact under <tag>,
which must be a full registry reference.

Local vulnerability reports are attached as a separate OCI referrer, so
re-scanning and pushing again refreshes them without changing the
package's digest. Afterwards, all but the newest --keep-reports report
referrers are deleted (best-effort: "bomify security prune" retries if
the registry refuses).

--sign signs the package, and its reports separately, before the tag
moves, so the tag never points at an unsigned package.

Provenance recorded by "bomify build --provenance" is attached as an
in-toto attestation, signed as a DSSE envelope with --sign, or unsigned
without it.

--vex (repeatable) attaches a VEX document, a name from "bomify security
vex add" or a file, as its own referrer; one already attached isn't
added again. A pull's gate honors it only when the pull verifies
signatures and the document's own signature verifies.

--quiet prints only the pinned reference, <repository>@<digest>, with no
progress or info logging.`

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
	publishFlags
	keepReports int
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

	opts.register(cmd, "upload", "print only the pushed package's pinned reference (<repository>@<digest>), with no progress or informational logging")
	cmd.Flags().IntVar(&opts.keepReports, "keep-reports", 1, "number of newest vulnerability report referrers to keep on the registry after pushing; older ones are deleted (0 keeps them all)")

	return cmd
}

func runPush(cmd *cobra.Command, tag string, opts *pushOptions) error {
	logger := opts.logger(cmd)

	sbomHash, err := build.ResolveTag(dataDir, tag)
	if err != nil {
		return err
	}

	repo, err := newRepository(tag)
	if err != nil {
		return err
	}

	transferOpts, done, err := opts.options(cmd, logger)
	if err != nil {
		return err
	}
	result, err := push.Push(cmd.Context(), repo, tag, dataDir, sbomHash, transferOpts)
	done()
	if err != nil {
		return err
	}

	logPushedLayers(logger, result)
	pruneReports(cmd.Context(), logger, repo, result.Manifest, opts.keepReports)

	opts.printPinned(cmd, tag, result.ManifestDigest)
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
	for _, referrer := range result.Attached {
		logger.Info("attached", "artifactType", referrer.ArtifactType, "digest", referrer.Digest.String())
	}
	if result.Provenance.Digest != "" {
		logger.Info("provenance attached", "digest", result.Provenance.Digest.String())
	}
}
