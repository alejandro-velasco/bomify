package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"bomify/internal/plugin"
	"bomify/internal/sbom"
)

// forEachComponent loads the SBOM at sbomPath, logs a summary, and calls fn
// for every component it describes. fn receives a logger already scoped to
// that component.
func forEachComponent(sbomPath string, logger *slog.Logger, fn func(component cdx.Component, log *slog.Logger) error) error {
	logger.Debug("loading sbom", "path", sbomPath)

	bom, err := sbom.Load(sbomPath)
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

	if bom.Components == nil {
		return nil
	}

	for _, component := range *bom.Components {
		log := logger.With("component", component.Name, "version", component.Version)
		if err := fn(component, log); err != nil {
			return fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
		}
	}

	return nil
}

// resolvePlugin detects the plugin kind for component and locates its
// binary on PATH, logging along the way.
func resolvePlugin(component cdx.Component, log *slog.Logger) (kind, path string, err error) {
	kind, err = plugin.Detect(component)
	if err != nil {
		log.Error("failed to detect plugin kind", "error", err)
		return "", "", fmt.Errorf("detect plugin kind: %w", err)
	}

	path, err = plugin.Find(kind)
	if err != nil {
		return "", "", err
	}

	return kind, path, nil
}
