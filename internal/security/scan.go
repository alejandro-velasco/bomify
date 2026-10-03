package security

import (
	"fmt"
	"log/slog"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/sync/errgroup"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

// Skipped is a component Scan didn't scan, and why.
type Skipped struct {
	Component cdx.Component
	// Reason says why, e.g. `unsupported type "generic"`.
	Reason string
}

// Scan scans every component in components through the scanning plugin
// at pluginPath — scanner names its type (bomify-plugin-<scanner>) — and
// returns each one's vulnerability report (see NewReport), in components'
// order. Nothing is written: callers decide whether, and when, to keep
// them (see WriteReport).
//
// The plugin is first asked, once, which purl types it supports
// ("security supported-components"); a component of any other type, or
// whose type can't be detected, gets no report and is returned as
// skipped, in components' order, so callers can say what wasn't
// checked (see Gate.FailOnUnscanned). A purl listed more than once is
// only scanned once, and not counted as skipped. The rest are scanned up
// to concurrency at a time (values less than 1 are treated as 1); any one
// failing fails the whole scan.
func Scan(pluginPath, scanner string, components []cdx.Component, concurrency int, logger *slog.Logger) ([]ComponentReport, []Skipped, error) {
	if concurrency < 1 {
		concurrency = 1
	}

	capabilities, err := supportedComponents(pluginPath, logger)
	if err != nil {
		return nil, nil, err
	}
	logger.Info("plugin capabilities", "types", capabilities.Types, "scans", capabilities.Scans)
	supportedTypes := make(map[string]bool, len(capabilities.Types))
	for _, t := range capabilities.Types {
		supportedTypes[t] = true
	}

	// Decided up front, sequentially, so which occurrence of a repeated
	// purl gets scanned doesn't depend on goroutine scheduling.
	toScan := make([]bool, len(components))
	claimed := map[string]bool{}
	var skipped []Skipped
	for i, component := range components {
		log := logger.With("component", component.Name, "version", component.Version)
		kind, err := plugin.Detect(component)
		if err != nil {
			log.Warn("skipping component: cannot determine its kind", "error", err)
			skipped = append(skipped, Skipped{Component: component, Reason: fmt.Sprintf("no detectable type: %v", err)})
			continue
		}
		if !supportedTypes[kind] {
			log.Info("skipping component: unsupported by this scanner", "kind", kind)
			skipped = append(skipped, Skipped{Component: component, Reason: fmt.Sprintf("unsupported type %q", kind)})
			continue
		}
		purlHash := layout.PurlHash(component.PackageURL)
		if claimed[purlHash] {
			log.Debug("skipping component: purl already scanned", "purl", component.PackageURL)
			continue
		}
		claimed[purlHash] = true
		toScan[i] = true
	}

	reports := make([]*cdx.BOM, len(components))
	var g errgroup.Group
	g.SetLimit(concurrency)
	for i, component := range components {
		if !toScan[i] {
			continue
		}
		g.Go(func() error {
			log := logger.With("component", component.Name, "version", component.Version)
			result, err := scanComponent(pluginPath, component, log)
			if err != nil {
				return fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
			}
			reports[i] = NewReport(component, result, scanner, time.Now())
			log.Info("scan complete", "vulnerabilities", len(result.Vulnerabilities), "components", len(result.Components))
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}

	var out []ComponentReport
	for i, report := range reports {
		if report != nil {
			out = append(out, ComponentReport{Component: components[i], Scanner: scanner, Report: report})
		}
	}
	return out, skipped, nil
}
