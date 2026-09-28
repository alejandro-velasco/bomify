// Package security stores the per-component vulnerability reports
// "bomify security scan" produces: one CycloneDX document per scanned
// component, under "<baseDir>/vulnerabilities/<purlHash>.json" — keyed by
// the same purl hash as that component's pull manifest and layer
// directory (see plugin.PurlHash), so two packages describing the same
// component share one report, the same way they share one pulled layer.
package security

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// ReportsDir returns the directory every vulnerability report under
// baseDir lives in.
func ReportsDir(baseDir string) string {
	return filepath.Join(baseDir, "vulnerabilities")
}

// ReportPath returns the deterministic path of the vulnerability report
// for the component whose purl hashes to purlHash.
func ReportPath(baseDir, purlHash string) string {
	return filepath.Join(ReportsDir(baseDir), purlHash+".json")
}

// NewReport builds component's vulnerability report from its scan
// result: a CycloneDX document whose metadata component is component
// itself, whose top-level components are whichever of the pieces the
// plugin unpacked component into (e.g. the packages cataloged inside an
// OCI image) some vulnerability's "affects" actually names — none, for a
// component scanned directly, or for one where nothing unpacked from it
// was affected — and whose vulnerabilities are exactly what the plugin
// reported, "affects" included.
//
// The report is shared by every package describing the same purl, so it
// must not carry anything specific to the one SBOM it happened to be
// scanned from: the metadata component's bom-ref is set to its purl —
// which is also what a plugin that scanned the purl directly names in
// "affects" (see plugins/SECURITY-CONTRACT.md) — rather than whatever
// bom-ref that SBOM gave it, and any nested components it declared there
// are dropped.
func NewReport(component cdx.Component, result pluginlib.SecurityResult) *cdx.BOM {
	subject := component
	subject.BOMRef = component.PackageURL
	subject.Components = nil

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &subject}

	affected := make(map[string]bool)
	for _, vuln := range result.Vulnerabilities {
		if vuln.Affects == nil {
			continue
		}
		for _, affects := range *vuln.Affects {
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

// WriteReport writes report as component's vulnerability report under
// baseDir, replacing any earlier one — a scan reflects the vulnerability
// data available at the time it ran, so the newest one always wins. The
// write is atomic (a temp file renamed into place), so a concurrent
// reader — or a crash mid-write — never sees a partial report. It
// returns the report's path.
func WriteReport(baseDir string, component cdx.Component, report *cdx.BOM) (string, error) {
	dir := ReportsDir(baseDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create vulnerabilities directory: %w", err)
	}

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetEscapeHTML(false)
	enc.SetPretty(true)
	if err := enc.Encode(report); err != nil {
		return "", fmt.Errorf("encode vulnerability report: %w", err)
	}

	path := ReportPath(baseDir, plugin.PurlHash(component))

	tmp, err := os.CreateTemp(dir, ".tmp-*.json")
	if err != nil {
		return "", fmt.Errorf("create temp report: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write temp report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp report: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return "", fmt.Errorf("chmod temp report: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("write report %s: %w", path, err)
	}

	return path, nil
}

// ReadReport reads the vulnerability report for the component whose purl
// hashes to purlHash.
func ReadReport(baseDir, purlHash string) (*cdx.BOM, error) {
	return sbom.Load(ReportPath(baseDir, purlHash))
}
