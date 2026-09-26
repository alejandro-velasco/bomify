package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

const securityShort = "Security scanning commands"

func securityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: securityShort,
	}

	cmd.AddCommand(securityScanCmd())

	return cmd
}

const securityScanShort = "Scan an SBOM's components for vulnerabilities via a security scanning plugin"

const securityScanLong = `Scan resolves a single "bomify-plugin-<type>" binary — <type> names the
scanning tool itself (e.g. "grype"), not a purl type or deployment
medium, since any scanner can in principle scan any component — and
first asks it, once, which component purl types and scan categories it
supports ("security supported-components"). Any component whose purl
type isn't in that list is skipped; every other component is scanned
via "security scan --purl <purl>", once per component, up to
--concurrency at a time: the same per-component, concurrent dispatch
"bomify build"/"bomify distribute" use, just for scanning instead of
pulling/pushing.

Each scan call reports the vulnerabilities that component's purl is
affected by; bomify itself sets each one's "affects" to that component
before merging results across every component — two components
separately reporting a vulnerability with the same "bom-ref" are merged
into one entry naming both components in "affects", rather than
duplicated. See plugins/SECURITY-CONTRACT.md for the full contract.

The scanned SBOM, with its "vulnerabilities" populated, is printed to
stdout by default; --output redirects it to a file instead.`

const securityScanExample = `  # Scan an SBOM for vulnerabilities with grype
  bomify security scan grype sbom.cdx.json

  # Scan up to 4 components concurrently, writing the result to a file
  bomify security scan grype sbom.cdx.json --concurrency 4 --output scanned.cdx.json`

type securityScanOptions struct {
	scanType    string
	sbomFile    string
	concurrency int
	output      string
}

func securityScanCmd() *cobra.Command {
	opts := &securityScanOptions{}

	cmd := &cobra.Command{
		Use:     "scan <type> <sbom-file>",
		Short:   securityScanShort,
		Long:    securityScanLong,
		Example: securityScanExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.scanType, opts.sbomFile = args[0], args[1]
			if err := runSecurityScan(cmd, opts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("security scan: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 1, "number of components to scan concurrently")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "file to write the scanned SBOM to (defaults to stdout)")

	return cmd
}

func runSecurityScan(cmd *cobra.Command, opts *securityScanOptions, logger *slog.Logger) error {
	path, err := plugin.Find(opts.scanType)
	if err != nil {
		return err
	}

	capabilities, err := plugin.SupportedComponents(path, logger)
	if err != nil {
		return err
	}
	logger.Info("plugin capabilities", "types", capabilities.Types, "scans", capabilities.Scans)
	supportedTypes := make(map[string]bool, len(capabilities.Types))
	for _, t := range capabilities.Types {
		supportedTypes[t] = true
	}

	bom, err := sbom.Load(opts.sbomFile)
	if err != nil {
		return err
	}

	merger := newVulnerabilityMerger()

	if err := forEachComponent(opts.sbomFile, logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		kind, err := plugin.Detect(component)
		if err != nil {
			log.Warn("skipping component: cannot determine its kind", "error", err)
			return nil
		}
		if !supportedTypes[kind] {
			log.Info("skipping component: unsupported by this scanner", "kind", kind)
			return nil
		}

		result, err := plugin.Scan(path, component, log)
		if err != nil {
			return err
		}
		log.Info("scan complete", "vulnerabilities", len(result))
		merger.add(component, result)
		return nil
	}); err != nil {
		return err
	}

	vulns := merger.result()
	bom.Vulnerabilities = &vulns

	w := cmd.OutOrStdout()
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			return fmt.Errorf("create output file %s: %w", opts.output, err)
		}
		defer f.Close()
		w = f
	}

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetEscapeHTML(false)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

// vulnerabilityMerger accumulates every component's scan result into one
// deduplicated vulnerability list, safe for concurrent use by
// forEachComponent's per-component goroutines.
type vulnerabilityMerger struct {
	mu    sync.Mutex
	vulns []cdx.Vulnerability
	byRef map[string]int // non-empty Vulnerability.BOMRef -> index into vulns
}

func newVulnerabilityMerger() *vulnerabilityMerger {
	return &vulnerabilityMerger{vulns: []cdx.Vulnerability{}, byRef: map[string]int{}}
}

// add folds component's scan result into m: each vulnerability's Affects
// is set to component's own reference (its bom-ref, or its purl if it
// has none), then merged into an already-collected entry sharing the
// same, non-empty Vulnerability.BOMRef instead of being appended as a
// duplicate — per plugins/SECURITY-CONTRACT.md's dedup rule. A
// vulnerability with no bom-ref of its own is never deduplicated: two
// unrelated findings that both happen to omit one would otherwise be
// silently merged under a shared empty key, hiding a real result.
func (m *vulnerabilityMerger) add(component cdx.Component, result []cdx.Vulnerability) {
	ref := componentRef(component)

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, v := range result {
		affects := []cdx.Affects{{Ref: ref}}
		if v.Affects != nil {
			affects = append(affects, *v.Affects...)
		}
		v.Affects = &affects

		if v.BOMRef == "" {
			m.vulns = append(m.vulns, v)
			continue
		}

		if i, ok := m.byRef[v.BOMRef]; ok {
			m.vulns[i].Affects = mergeAffects(m.vulns[i].Affects, v.Affects)
			continue
		}

		m.byRef[v.BOMRef] = len(m.vulns)
		m.vulns = append(m.vulns, v)
	}
}

// result returns every vulnerability m has collected so far.
func (m *vulnerabilityMerger) result() []cdx.Vulnerability {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vulns
}

// componentRef returns the reference a vulnerability's Affects should
// name component by: its own bom-ref if it has one, falling back to its
// purl for an SBOM whose components were never assigned one.
func componentRef(component cdx.Component) string {
	if component.BOMRef != "" {
		return component.BOMRef
	}
	return component.PackageURL
}

// mergeAffects returns existing with incoming's entries appended,
// deduplicated by Ref — the same component reported twice (e.g. a
// plugin returning the same vulnerability more than once) still only
// appears once in the merged result.
func mergeAffects(existing, incoming *[]cdx.Affects) *[]cdx.Affects {
	seen := map[string]bool{}
	merged := []cdx.Affects{}

	for _, list := range []*[]cdx.Affects{existing, incoming} {
		if list == nil {
			continue
		}
		for _, a := range *list {
			if seen[a.Ref] {
				continue
			}
			seen[a.Ref] = true
			merged = append(merged, a)
		}
	}

	return &merged
}
