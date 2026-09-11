package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"bomify/internal/logging"
	"bomify/internal/plugin"
)

type buildOptions struct {
	file   string
	output string
}

// buildCmd builds the `bomify build` command.
func buildCmd() *cobra.Command {

	buildOpts := &buildOptions{}

	buildCmd := &cobra.Command{
		Use:   "build",
		Short: "Build builds the package described by a CycloneDX SBOM",
		Long:  "Build reads a CycloneDX SBOM and builds a containing each component it describes.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runBuild(buildOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("build: %w", err)
			}
			return nil
		},
	}

	buildCmd.Flags().StringVarP(&buildOpts.file, "file", "f", "", "path to the CycloneDX SBOM file (JSON or XML)")
	buildCmd.Flags().StringVarP(&buildOpts.output, "output", "o", "dist", "directory to write components to")
	_ = buildCmd.MarkFlagRequired("file")

	return buildCmd
}

func runBuild(opts *buildOptions, logger *slog.Logger) error {
	return forEachComponent(opts.file, logger, func(component cdx.Component, log *slog.Logger) error {
		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path)

		result, err := plugin.Pull(path, component, opts.output)
		if err != nil {
			return err
		}

		log.Info("pull complete", "output", result.OutputPath, "message", result.Message)

		return nil
	})
}
