package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/sync/errgroup"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

// forEachComponent loads the SBOM at sbomPath, logs a summary, and calls fn
// for every component it describes, running up to concurrency components
// at once (concurrency < 1 is treated as 1, i.e. sequential). fn receives
// a logger already scoped to that component. The first error any
// component returns aborts the rest and is returned, wrapped with that
// component's identity.
func forEachComponent(sbomPath string, logger *slog.Logger, concurrency int, fn func(component cdx.Component, log *slog.Logger) error) error {
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

	logger.Info("loaded sbom", "name", name, "components", componentCount, "concurrency", concurrency)

	if bom.Components == nil {
		return nil
	}

	if concurrency < 1 {
		concurrency = 1
	}

	var g errgroup.Group
	g.SetLimit(concurrency)

	for _, component := range *bom.Components {
		g.Go(func() error {
			log := logger.With("component", component.Name, "version", component.Version)
			if err := fn(component, log); err != nil {
				return fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
			}
			return nil
		})
	}

	return g.Wait()
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
