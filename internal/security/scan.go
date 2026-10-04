package security

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/sync/errgroup"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// ScanPlugin is one scanning plugin ScanAll scans with: its type (the
// scanner bomify-plugin-<Name> is), and where it's installed.
type ScanPlugin struct {
	Name string
	Path string
}

// ScanOptions are how ScanAll scans.
type ScanOptions struct {
	// Concurrency bounds how many components a plugin scans at once;
	// values less than 1 are treated as 1.
	Concurrency int
	// ContentDir is the data directory holding the components' pulled
	// files (see layout.ComponentLayer), passed to a plugin as "security
	// scan --input" for the types it scans from them (ScanByFiles). Empty
	// when the files aren't there, as on a scan on pull, which runs before
	// anything is written: such components are then skipped.
	ContentDir string
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
// another, each as scanPlugin does: each component gets a report from
// every plugin that supports it. Any scan failing fails it.
func ScanAll(plugins []ScanPlugin, components []cdx.Component, opts ScanOptions, logger *slog.Logger) (ScanResult, error) {
	result := ScanResult{Components: len(components)}
	// unscanned are the components (see componentKey) every plugin so far
	// skipped; skippedByFirst is what the first plugin skipped, why, and in
	// what order.
	var unscanned map[string]bool
	var skippedByFirst []Skipped
	for i, p := range plugins {
		reports, skipped, err := scanPlugin(p, components, opts, logger.With("scanner", p.Name))
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

// Skipped is a component a scan didn't scan, and why.
type Skipped struct {
	Component cdx.Component
	// Reason says why, e.g. `unsupported type "generic"`.
	Reason string
}

// scanPlugin scans every component in components through the scanning
// plugin p and returns each one's vulnerability report (see NewReport),
// in components' order. Nothing is written: callers decide whether, and
// when, to keep them (see WriteReport).
//
// The plugin is first asked, once, which purl types it supports and how
// ("security supported-components"). It scans a component of a type it
// scans by purl; one of a type it scans from files only with the
// component's files, passed as --input from opts.ContentDir; and no
// other. A component it doesn't
// scan, whose type can't be detected, or that the plugin reports it
// couldn't analyze (SecurityResult.Unscanned) gets no report and is
// returned as skipped, in components' order, so callers can say what
// wasn't checked (see Gate.FailOnUnscanned). A purl listed more than once
// is only scanned once, and not counted as skipped. The rest are scanned
// up to opts.Concurrency at a time; any one failing fails the whole scan.
func scanPlugin(p ScanPlugin, components []cdx.Component, opts ScanOptions, logger *slog.Logger) ([]ComponentReport, []Skipped, error) {
	concurrency := max(opts.Concurrency, 1)

	capabilities, err := supportedComponents(p.Path, logger)
	if err != nil {
		return nil, nil, err
	}
	logger.Info("plugin capabilities", "types", capabilities.Types, "scans", capabilities.Scans)

	// Decided up front, sequentially, so which occurrence of a repeated
	// purl gets scanned doesn't depend on goroutine scheduling. inputs
	// holds the --input of each component scanned with one.
	toScan := make([]bool, len(components))
	inputs := make([]string, len(components))
	skippedAt := make([]*Skipped, len(components))
	skip := func(i int, reason string) {
		skippedAt[i] = &Skipped{Component: components[i], Reason: reason}
	}
	claimed := map[string]bool{}
	for i, component := range components {
		log := logger.With("component", component.Name, "version", component.Version)
		kind, err := plugin.Detect(component)
		if err != nil {
			log.Warn("skipping component: cannot determine its kind", "error", err)
			skip(i, fmt.Sprintf("no detectable type: %v", err))
			continue
		}
		switch mode := capabilities.Types[kind]; mode {
		case pluginlib.ScanByPurl:
		case pluginlib.ScanByFiles:
			if inputs[i] = componentFiles(opts.ContentDir, component); inputs[i] == "" {
				log.Info("skipping component: the scanner needs its files, which this scan doesn't have", "kind", kind)
				skip(i, fmt.Sprintf("type %q is scanned from its pulled files, which this scan doesn't have", kind))
				continue
			}
		case "":
			log.Info("skipping component: unsupported by this scanner", "kind", kind)
			skip(i, fmt.Sprintf("unsupported type %q", kind))
			continue
		default:
			// A mode from a newer plugin than this bomify knows.
			log.Warn("skipping component: unknown scan mode", "kind", kind, "mode", mode)
			skip(i, fmt.Sprintf("type %q is scanned by %q, which this bomify doesn't know", kind, mode))
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
			result, err := scanComponent(p.Path, component, inputs[i], log)
			if err != nil {
				return fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
			}
			if result.Unscanned != "" {
				log.Info("scanner couldn't analyze component", "reason", result.Unscanned)
				skip(i, fmt.Sprintf("%s couldn't analyze it: %s", p.Name, result.Unscanned))
				return nil
			}
			reports[i] = NewReport(component, result, p.Name, time.Now())
			log.Info("scan complete", "vulnerabilities", len(result.Vulnerabilities), "components", len(result.Components))
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, nil, err
	}

	var out []ComponentReport
	var skipped []Skipped
	for i, report := range reports {
		if report != nil {
			out = append(out, ComponentReport{Component: components[i], Scanner: p.Name, Report: report})
		}
		if skippedAt[i] != nil {
			skipped = append(skipped, *skippedAt[i])
		}
	}
	return out, skipped, nil
}

// componentFiles returns the directory under contentDir holding
// component's pulled files (see layout.ComponentLayer), or "" if
// contentDir is empty or there are none.
func componentFiles(contentDir string, component cdx.Component) string {
	if contentDir == "" {
		return ""
	}
	dir := layout.ComponentLayer(contentDir, component.PackageURL)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return ""
	}
	return dir
}
