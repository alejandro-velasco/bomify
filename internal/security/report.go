// Package security stores the per-component vulnerability reports
// "bomify security scan" produces: one CycloneDX document per scanned
// component and scanner, under
// "<baseDir>/vulnerabilities/<purlHash>/<scanner>.json" — keyed by the
// same purl hash as that component's pull manifest and layer directory
// (see plugin.PurlHash), so two packages describing the same component
// share its reports, the same way they share one pulled layer.
package security

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// NewReport builds component's vulnerability report from its scan
// result: a CycloneDX document whose metadata component is component
// itself, whose top-level components are whichever of the pieces the
// plugin unpacked component into (e.g. the packages cataloged inside an
// OCI image) some vulnerability's "affects" actually names — none, for a
// component scanned directly, or for one where nothing unpacked from it
// was affected — and whose vulnerabilities are exactly what the plugin
// reported, "affects" included.
//
// The report is shared by every package describing the same purl, so it must
// not carry anything specific to the one SBOM it happened to be scanned from:
// the metadata component's bom-ref is set to its purl — which is also what a
// plugin that scanned the purl directly names in "affects" (see
// plugins/contracts/security/v1/CONTRACT.md) — rather than whatever bom-ref
// that SBOM gave it, and any nested components it declared there are dropped.
//
// scanner (the scanning plugin's type) and scannedAt are recorded as the
// report's metadata tool and timestamp, which is how a package's report
// referrer is dated (see Attach). A zero scannedAt records no timestamp.
func NewReport(component cdx.Component, result pluginlib.SecurityResult, scanner string, scannedAt time.Time) *cdx.BOM {
	subject := component
	subject.BOMRef = component.PackageURL
	subject.Components = nil

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &subject}
	if !scannedAt.IsZero() {
		bom.Metadata.Timestamp = scannedAt.UTC().Format(time.RFC3339)
	}
	if scanner != "" {
		bom.Metadata.Tools = &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type: cdx.ComponentTypeApplication,
			Name: scanner,
		}}}
	}

	affected := make(map[string]bool)
	for _, vuln := range result.Vulnerabilities {
		for _, affects := range sliceutil.Deref(vuln.Affects) {
			affected[affects.Ref] = true
		}
	}

	components := make([]cdx.Component, 0, len(result.Components))
	for _, c := range result.Components {
		if affected[c.BOMRef] {
			components = append(components, c)
		}
	}
	bom.Components = &components

	vulns := result.Vulnerabilities
	if vulns == nil {
		vulns = []cdx.Vulnerability{}
	}
	bom.Vulnerabilities = &vulns

	return bom
}

// WriteReport writes r.Report as r.Scanner's vulnerability report of
// r.Component under baseDir, replacing that scanner's earlier one — a
// scan reflects the vulnerability data available at the time it ran, so
// the newest one wins — and leaving other scanners' alone. The write is
// atomic (a temp file renamed into place), so a concurrent reader — or a
// crash mid-write — never sees a partial report. It returns the report's
// path.
func WriteReport(baseDir string, r ComponentReport) (string, error) {
	if err := CheckScanner(r.Scanner); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetEscapeHTML(false)
	enc.SetPretty(true)
	if err := enc.Encode(r.Report); err != nil {
		return "", fmt.Errorf("encode vulnerability report: %w", err)
	}

	path := layout.Report(baseDir, layout.PurlHash(r.Component.PackageURL), r.Scanner)
	if err := fsutil.WriteFileAtomic(path, buf.Bytes()); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}

	return path, nil
}

// CheckScanner fails unless scanner can name a vulnerability report: set,
// and usable as a file name, since it is one (see layout.Report). A name
// from a registry annotation must pass it before it's used.
func CheckScanner(scanner string) error {
	if scanner == "" {
		return fmt.Errorf("a vulnerability report needs the scanner that produced it")
	}
	if !transfer.IsSafeFilename(scanner) {
		return fmt.Errorf("scanner %q can't name a vulnerability report", scanner)
	}
	return nil
}

// CheckScanners fails unless scanners, scanning plugins' names as given
// on the command line or in a Rule, are at least one, each named at most
// once, and each usable as a report's name (see CheckScanner).
func CheckScanners(scanners []string) error {
	if len(scanners) == 0 {
		return fmt.Errorf("no scanner given")
	}
	for i, scanner := range scanners {
		// An empty name in a list is a stray comma, e.g. "grype,".
		if scanner == "" {
			return fmt.Errorf("empty scanner name in %q", strings.Join(scanners, ","))
		}
		if err := CheckScanner(scanner); err != nil {
			return err
		}
		if slices.Contains(scanners[:i], scanner) {
			return fmt.Errorf("scanner %q given more than once", scanner)
		}
	}
	return nil
}

// StoredReport is one scanner's vulnerability report of a component, as
// kept under the data directory.
type StoredReport struct {
	Scanner string
	Path    string
}

// ReadReports lists every scanner's vulnerability report of the component
// whose purl hashes to purlHash, sorted by scanner; none if it has none.
func ReadReports(baseDir, purlHash string) ([]StoredReport, error) {
	dir := layout.ComponentReports(baseDir, purlHash)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var reports []StoredReport
	for _, entry := range entries {
		// A report is <scanner>.json, as WriteReport names it. Anything
		// else, such as an in-flight write's temp file (".tmp-*", see
		// fsutil.WriteFileAtomic), isn't one.
		scanner, isReport := strings.CutSuffix(entry.Name(), ".json")
		if !isReport || entry.IsDir() || CheckScanner(scanner) != nil {
			continue
		}
		reports = append(reports, StoredReport{Scanner: scanner, Path: layout.Report(baseDir, purlHash, scanner)})
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Scanner < reports[j].Scanner })
	return reports, nil
}
