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
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
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
affected by, and sets each one's "affects" itself — to the purl it was
given, or, if it had to unpack that purl into smaller pieces to scan it
at all (e.g. cataloging a container image's contents), to the specific
piece(s) actually affected. bomify only merges results across every
component: two separate scans reporting a vulnerability with the same
"bom-ref" are folded into one entry combining both "affects", rather
than duplicated; any pieces a plugin reports unpacking a component into
are embedded as that component's own nested components. See
plugins/SECURITY-CONTRACT.md for the full contract.

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
		log.Info("scan complete", "vulnerabilities", len(result.Vulnerabilities), "components", len(result.Components))
		merger.add(component, result)
		return nil
	}); err != nil {
		return err
	}

	merger.applyNestedComponents(bom.Components)

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
	mu                 sync.Mutex
	vulns              []cdx.Vulnerability
	byRef              map[string]int // non-empty Vulnerability.BOMRef -> index into vulns
	componentsByParent map[string][]cdx.Component
}

func newVulnerabilityMerger() *vulnerabilityMerger {
	return &vulnerabilityMerger{
		vulns:              []cdx.Vulnerability{},
		byRef:              map[string]int{},
		componentsByParent: map[string][]cdx.Component{},
	}
}

// add folds component's scan result into m. Every vulnerability's
// Affects is left exactly as the plugin reported it — bomify no longer
// sets or overwrites it — merged into an already-collected entry
// sharing the same, non-empty Vulnerability.BOMRef instead of being
// appended as a duplicate — per plugins/SECURITY-CONTRACT.md's dedup
// rule. A vulnerability with no bom-ref of its own is never
// deduplicated: two unrelated findings that both happen to omit one
// would otherwise be silently merged under a shared empty key, hiding a
// real result. result.Components (if any) are recorded to be embedded
// under component itself once every component has been scanned — see
// applyNestedComponents.
func (m *vulnerabilityMerger) add(component cdx.Component, result pluginlib.SecurityResult) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(result.Components) > 0 {
		ref := componentRef(component)
		m.componentsByParent[ref] = append(m.componentsByParent[ref], result.Components...)
	}

	for _, v := range result.Vulnerabilities {
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

// applyNestedComponents embeds every component discovered while
// unpacking a top-level component to scan it (see add) as that
// component's own nested Components, in place within components. Called
// once forEachComponent has finished, after every concurrent scan has
// already returned, so it doesn't need m's mutex.
func (m *vulnerabilityMerger) applyNestedComponents(components *[]cdx.Component) {
	if components == nil {
		return
	}

	for i := range *components {
		nested, ok := m.componentsByParent[componentRef((*components)[i])]
		if !ok {
			continue
		}
		(*components)[i].Components = &nested
	}
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
