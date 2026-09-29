package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/signature"
)

const pushShort = "Publish a bomify package to an OCI registry"

const pushLong = `Push packages the SBOM manifest a prior "bomify build" recorded for
<tag> (and each component it describes) as an OCI artifact, and
publishes it under <tag>. <tag> is both the local bookkeeping key
(see "bomify tag" / "bomify packages") and the destination reference.

Any component with a local vulnerability report from a prior "bomify
security scan" is pushed an extra layer carrying it; a component never
scanned carries none.

--sign signs the pushed package with a signing plugin before <tag> is
updated to point at it, attaching the signature to it as an OCI
referrer. One signature covers the whole package: the SBOM, every
component, and every vulnerability report. See "bomify pull --verify"
and "bomify trust" for checking it.

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
	sign        signFlags
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
	opts.sign.register(cmd)

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

	result, err := push.Push(cmd.Context(), repo, tag, dataDir, sbomHash, opts.concurrency, progress, signer)
	if err != nil {
		return err
	}

	logPushedLayers(logger, result)

	if opts.quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "%s@%s\n", signature.Repository(tag), result.ManifestDigest)
	}
	return nil
}

func logPushedLayers(logger *slog.Logger, result push.Result) {
	logger.Info("manifest pushed", "digest", result.ManifestDigest)
	for _, layer := range result.Layers {
		logger.Info("layer pushed", "purl", layer.Purl, "hash", layer.Hash)
	}
	for _, report := range result.VulnerabilityReports {
		logger.Info("vulnerability report attached", "purl", report.Purl, "hash", report.Hash)
	}
}
