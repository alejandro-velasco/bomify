package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

type distributeOptions struct {
	file        string
	remote      string
	concurrency int
}

func distributeCmd() *cobra.Command {
	distributeOpts := &distributeOptions{}

	distributeCmd := &cobra.Command{
		Use:   "distribute <sbom-file>",
		Short: "Distribute publishes the packages described by a CycloneDX SBOM to a remote endpoint",
		Long:  "Distribute reads a CycloneDX SBOM and publishes each component it describes to a remote endpoint.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			distributeOpts.file = args[0]
			if err := runDistribute(distributeOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("distribute: %w", err)
			}
			return nil
		},
	}

	distributeCmd.Flags().StringVarP(&distributeOpts.remote, "remote", "r", "", "remote endpoint to distribute components to")
	distributeCmd.Flags().IntVarP(&distributeOpts.concurrency, "concurrency", "c", 1, "number of components to push concurrently")
	_ = distributeCmd.MarkFlagRequired("remote")

	return distributeCmd
}

func runDistribute(opts *distributeOptions, logger *slog.Logger) error {
	return forEachComponent(opts.file, logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path)

		result, err := plugin.Push(path, component, dataDir, opts.remote, log)
		if err != nil {
			return err
		}

		log.Info("push complete", "output", result.OutputPath, "message", result.Message)

		return nil
	})
}
