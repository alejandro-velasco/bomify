package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"bomify/internal/logging"
	"bomify/internal/plugin"
	"bomify/internal/sbom"
)

type packageOptions struct {
	sbom   string
	output string
}

// packageCmd packages the `bomify package` command.
func packageCmd() *cobra.Command {

	packageOpts := &packageOptions{}

	packageCmd := &cobra.Command{
		Use:   "package",
		Short: "Package packages described by a CycloneDX SBOM",
		Long:  "Package reads a CycloneDX SBOM and packages a package for each component it describes.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackage(packageOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("package: %w", err)
			}
			return nil
		},
	}

	packageCmd.Flags().StringVar(&packageOpts.sbom, "sbom", "", "path to the CycloneDX SBOM file (JSON or XML)")
	packageCmd.Flags().StringVar(&packageOpts.output, "output", "dist", "directory to write components to")
	_ = packageCmd.MarkFlagRequired("sbom")

	return packageCmd
}

func runPackage(opts *packageOptions, logger *slog.Logger) error {
	logger.Debug("loading sbom", "path", opts.sbom)

	bom, err := sbom.Load(opts.sbom)
	if err != nil {
		return fmt.Errorf("load sbom: %w", err)
	}

	name := "unknown"
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		name = bom.Metadata.Component.Name
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	logger.Info("loaded sbom", "name", name, "components", componentCount)
	logger.Debug("resolved output directory", "path", opts.output)

	if bom.Components == nil {
		return nil
	}

	for _, component := range *bom.Components {
		if err := packageComponent(component, opts.output, logger); err != nil {
			return fmt.Errorf("package %s@%s: %w", component.Name, component.Version, err)
		}
	}

	return nil
}

// packageComponent packages a single SBOM component. Components matching a
// known plugin kind (e.g. container images) are delegated to the
// corresponding "bomify-package-<kind>" binary on PATH;
func packageComponent(component cdx.Component, output string, logger *slog.Logger) error {
	log := logger.With("component", component.Name, "version", component.Version)

	kind, err := plugin.Detect(component)
	if err != nil {
		log.Error("failed to detect package kind", "error", err)
		return fmt.Errorf("detect package kind: %w", err)
	}

	path, err := plugin.Find(kind)
	if err != nil {
		return err
	}

	log.Info("delegating to plugin", "kind", kind, "path", path)

	result, err := plugin.Run(path, component, output)
	if err != nil {
		return err
	}

	log.Info("package complete", "output", result.OutputPath, "message", result.Message)

	return nil
}
