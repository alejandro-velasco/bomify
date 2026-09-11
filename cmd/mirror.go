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
	file   string
	remote string
}

// mirrorCmd builds the `bomify mirror` command.
func mirrorCmd() *cobra.Command {
	mirrorOpts := &mirrorOptions{}

	mirrorCmd := &cobra.Command{
		Use:   "mirror",
		Short: "Mirror publishes the packages described by a CycloneDX SBOM to a remote endpoint",
		Long:  "Mirror reads a CycloneDX SBOM and publishes each component it describes to a remote endpoint.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runMirror(mirrorOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("mirror: %w", err)
			}
			return nil
		},
	}

	mirrorCmd.Flags().StringVarP(&mirrorOpts.file, "file", "f", "", "path to the CycloneDX SBOM file (JSON or XML)")
	mirrorCmd.Flags().StringVarP(&mirrorOpts.remote, "remote", "r", "", "remote endpoint to mirror components to")
	_ = mirrorCmd.MarkFlagRequired("file")
	_ = mirrorCmd.MarkFlagRequired("remote")

	return mirrorCmd
}

func runMirror(opts *mirrorOptions, logger *slog.Logger) error {
	return forEachComponent(opts.file, logger, func(component cdx.Component, log *slog.Logger) error {
		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path)

		result, err := plugin.Push(path, component, opts.remote)
		if err != nil {
			return err
		}

		log.Info("push complete", "output", result.OutputPath, "message", result.Message)

		return nil
	})
}
