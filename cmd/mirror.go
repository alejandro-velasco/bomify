package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"bomify/internal/logging"
	"bomify/internal/plugin"
)

type mirrorOptions struct {
	file        string
	output      string
	remote      string
	concurrency int
}

// mirrorCmd builds the `bomify mirror` command.
func mirrorCmd() *cobra.Command {
	mirrorOpts := &mirrorOptions{}

	mirrorCmd := &cobra.Command{
		Use:   "mirror <sbom-file>",
		Short: "Mirror publishes the packages described by a CycloneDX SBOM to a remote endpoint",
		Long:  "Mirror reads a CycloneDX SBOM and publishes each component it describes to a remote endpoint.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mirrorOpts.file = args[0]
			if err := runMirror(mirrorOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("mirror: %w", err)
			}
			return nil
		},
	}

	mirrorCmd.Flags().StringVarP(&mirrorOpts.output, "output", "o", "dist", "directory bomify build wrote components to")
	mirrorCmd.Flags().StringVarP(&mirrorOpts.remote, "remote", "r", "", "remote endpoint to mirror components to")
	mirrorCmd.Flags().IntVarP(&mirrorOpts.concurrency, "concurrency", "c", 1, "number of components to push concurrently")
	_ = mirrorCmd.MarkFlagRequired("remote")

	return mirrorCmd
}

func runMirror(opts *mirrorOptions, logger *slog.Logger) error {
	return forEachComponent(opts.file, logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path)

		result, err := plugin.Push(path, component, opts.output, opts.remote)
		if err != nil {
			return err
		}

		log.Info("push complete", "output", result.OutputPath, "message", result.Message)

		return nil
	})
}
