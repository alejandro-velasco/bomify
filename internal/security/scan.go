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

// ScanPlugin is one scanning plugin ScanAll scans with: its type (the
// scanner bomify-plugin-<Name> is), and where it's installed.
type ScanPlugin struct {
	Name string
	Path string
}

// ScanResult is what ScanAll found.
type ScanResult struct {
	// Scanners are the scanners that scanned, by name.
	Scanners []string
	// Components is how many components were given to scan.
	Components int
	// Reports holds every scanner's report of every component it
	// supports, each recording its scanner (see ComponentReport.Scanner).
	Reports []ComponentReport
	// Skipped are the components no scanner scanned, in the order they
	// were given, each once.
	Skipped []Skipped
}

// ScanAll scans components with every plugin in plugins, one plugin after
// another, each as Scan does: each component gets a report from every
// plugin that supports it. Any scan failing fails it.
func ScanAll(plugins []ScanPlugin, components []cdx.Component, concurrency int, logger *slog.Logger) (ScanResult, error) {
	result := ScanResult{Components: len(components)}
	// unscanned are the components (see componentKey) every plugin so far
	// skipped; skippedByFirst is what the first plugin skipped, why, and in
	// what order.
	var unscanned map[string]bool
	var skippedByFirst []Skipped
	for i, p := range plugins {
		reports, skipped, err := Scan(p.Path, p.Name, components, concurrency, logger.With("scanner", p.Name))
		if err != nil {
			return ScanResult{}, fmt.Errorf("%s: %w", p.Name, err)
		}
		result.Scanners = append(result.Scanners, p.Name)
		result.Reports = append(result.Reports, reports...)

		skippedByThis := map[string]bool{}
		for _, s := range skipped {
			skippedByThis[componentKey(s.Component)] = true
		}
		if i == 0 {
			skippedByFirst, unscanned = skipped, skippedByThis
			continue
		}
		for key := range unscanned {
			if !skippedByThis[key] {
				delete(unscanned, key) // this plugin scanned it
			}
		}
	}

	// A component every plugin skipped was skipped by the first, for the
	// same reason (detecting its type doesn't depend on the plugin), so
	// its list gives each one's reason, in components' order. Deleting
	// each as it's listed lists a repeated component once.
	for _, s := range skippedByFirst {
		key := componentKey(s.Component)
		if unscanned[key] {
			delete(unscanned, key)
			result.Skipped = append(result.Skipped, s)
		}
	}
	return result, nil
}

// componentKey identifies component for ScanAll: its purl, or, without
// one, its name and version.
func componentKey(component cdx.Component) string {
	if component.PackageURL != "" {
		return component.PackageURL
	}
	return component.Name + "@" + component.Version
}

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
