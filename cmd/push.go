package cmd

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
)

type pushOptions struct {
	concurrency int
}

func pushCmd() *cobra.Command {
	opts := &pushOptions{}

	cmd := &cobra.Command{
		Use:   "push <tag>",
		Short: "Push publishes a bomify package to an OCI registry",
		Long:  "Push packages the SBOM manifest a prior `bomify build` recorded for <tag> (and each component it describes) as an OCI artifact, and publishes it under <tag>. <tag> is both the local bookkeeping key (see `bomify tag`/`bomify packages`) and the destination reference, exactly like `docker push`.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPush(cmd, args[0], opts); err != nil {
				return fmt.Errorf("push: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 3, "number of layers to upload concurrently")

	return cmd
}

func runPush(cmd *cobra.Command, tag string, opts *pushOptions) error {
	logger := logging.FromContext(cmd.Context())

	sbomHash, err := build.ResolveTag(dataDir, tag)
	if err != nil {
		return err
	}

	repo, err := newRepository(tag)
	if err != nil {
		return err
	}

	mb := newMultiBar(cmd.OutOrStderr())
	progress := newProgressFunc(mb)

	result, err := push.Push(cmd.Context(), repo, tag, dataDir, sbomHash, opts.concurrency, progress)
	if err != nil {
		return err
	}

	logPushedLayers(logger, result)

	return nil
}

func logPushedLayers(logger *slog.Logger, result push.Result) {
	logger.Info("manifest pushed", "digest", result.ManifestDigest)
	for _, layer := range result.Layers {
		logger.Info("layer pushed", "purl", layer.Purl, "hash", layer.Hash)
	}
}
