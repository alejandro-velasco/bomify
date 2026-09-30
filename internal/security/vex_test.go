package security

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/openvex/go-vex/pkg/vex"
)

const (
	imagePurl = "pkg:oci/app@sha256%3Aabc?repository_url=registry.example.com/app"
	pkgA      = "pkg:apk/alpine/openssl@3.1.0-r0?arch=x86_64"
	pkgB      = "pkg:apk/alpine/zlib@1.3-r0?arch=x86_64"
)

func writeVEX(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func loadVEX(t *testing.T, bodies ...string) *VEX {
	t.Helper()
	var paths []string
	for i, body := range bodies {
		paths = append(paths, writeVEX(t, "vex"+string(rune('a'+i))+".json", body))
	}
	v, err := LoadVEX(paths)
	if err != nil {
		t.Fatalf("LoadVEX: %v", err)
	}
	return v
}

// imageReport is an image's report whose one vulnerability, CVE-1
// (alias GHSA-1), affects the packages named by affected.
func imageReport(affected ...string) ComponentReport {
	var affects []cdx.Affects
	var components []cdx.Component
	for _, purl := range affected {
		affects = append(affects, cdx.Affects{Ref: purl})
		components = append(components, cdx.Component{BOMRef: purl, PackageURL: purl})
	}
	high := []cdx.VulnerabilityRating{{Severity: cdx.SeverityHigh}}
	refs := []cdx.VulnerabilityReference{{ID: "GHSA-1"}}
	vulns := []cdx.Vulnerability{{ID: "CVE-1", Ratings: &high, Affects: &affects, References: &refs}}
	return ComponentReport{
		Component: cdx.Component{PackageURL: imagePurl},
		Report:    &cdx.BOM{Components: &components, Vulnerabilities: &vulns},
	}
}

// directReport is a directly-scanned component's report with one high
// vulnerability, CVE-1, affecting the component itself.
func directReport(purl string) ComponentReport {
	r := imageReport(purl)
	r.Component = cdx.Component{PackageURL: purl}
	r.Report.Components = nil
	return r
}

func gateWith(v *VEX) Gate { return Gate{FailOn: SeverityHigh, VEX: v} }

func TestCycloneDXVEX(t *testing.T) {
	notAffected := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
		"components":[{"bom-ref":"openssl","type":"library","name":"openssl","purl":"pkg:apk/alpine/openssl@3.1.0-r0"}],
		"vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected","justification":"code_not_reachable"},
			"affects":[{"ref":"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#openssl"}]}]}`
	exploitable := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
		"vulnerabilities":[{"id":"CVE-1","analysis":{"state":"exploitable"},"affects":[{"ref":"pkg:apk/alpine/openssl@3.1.0-r0"}]}]}`

	report := directReport(pkgA)

	// Resolved through the VEX document's own bom-ref (via a BOM-Link),
	// and matched despite the report's purl carrying a qualifier.
	e := gateWith(loadVEX(t, notAffected)).Evaluate([]ComponentReport{report})
	if len(e.Findings) != 0 || len(e.Suppressed) != 1 {
		t.Fatalf("not_affected: %+v, want CVE-1 suppressed", e)
	}
	if s := e.Suppressed[0].Statement; s.Status != vex.StatusNotAffected || s.Justification != "code_not_reachable" || s.Source == "" {
		t.Errorf("statement = %+v", s)
	}

	// A later document saying it's exploitable wins.
	if e := gateWith(loadVEX(t, notAffected, exploitable)).Evaluate([]ComponentReport{report}); len(e.Findings) != 1 {
		t.Errorf("not_affected then exploitable: %+v, want CVE-1 to fail", e)
	}
}

func TestOpenVEX(t *testing.T) {
	doc := func(statements string) string {
		return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","timestamp":"2026-01-01T00:00:00Z","statements":[` + statements + `]}`
	}
	notAffectedInA := `{"vulnerability":{"name":"GHSA-1"},"products":[{"@id":"` + imagePurl + `",
		"subcomponents":[{"@id":"pkg:apk/alpine/openssl@3.1.0-r0"}]}],"status":"not_affected","justification":"vulnerable_code_not_present"}`
	notAffectedInB := `{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/app@sha256%3Aabc",
		"subcomponents":[{"identifiers":{"purl":"` + pkgB + `"}}]}],"status":"not_affected","justification":"component_not_present"}`

	both := imageReport(pkgA, pkgB)

	// Only one of the two affected packages is cleared: still fails.
	if e := gateWith(loadVEX(t, doc(notAffectedInA))).Evaluate([]ComponentReport{both}); len(e.Findings) != 1 {
		t.Errorf("one of two cleared: %+v, want CVE-1 to fail", e)
	}
	// Both cleared (one by alias, one by a purl identifier): suppressed.
	if e := gateWith(loadVEX(t, doc(notAffectedInA+","+notAffectedInB))).Evaluate([]ComponentReport{both}); len(e.Findings) != 0 || len(e.Suppressed) != 1 {
		t.Errorf("both cleared: %+v, want CVE-1 suppressed", e)
	}

	// A statement for the whole image, with no subcomponents, clears it
	// everywhere inside.
	whole := `{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"` + imagePurl + `"}],"status":"fixed"}`
	if e := gateWith(loadVEX(t, doc(whole))).Evaluate([]ComponentReport{both}); len(e.Findings) != 0 {
		t.Errorf("whole image fixed: %+v, want CVE-1 suppressed", e)
	}

	// By timestamp, a later "affected" beats an earlier "not_affected",
	// whatever order they're listed in.
	later := `{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"` + imagePurl + `"}],"status":"affected","timestamp":"2026-06-01T00:00:00Z"}`
	if e := gateWith(loadVEX(t, doc(later+","+whole))).Evaluate([]ComponentReport{both}); len(e.Findings) != 1 {
		t.Errorf("later affected: %+v, want CVE-1 to fail", e)
	}

	// A statement about another product doesn't apply.
	other := `{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/other@1"}],"status":"not_affected"}`
	if e := gateWith(loadVEX(t, doc(other))).Evaluate([]ComponentReport{both}); len(e.Findings) != 1 {
		t.Errorf("other product: %+v, want CVE-1 to fail", e)
	}
}

func TestReportAnalysisExempts(t *testing.T) {
	report := directReport(pkgA)
	(*report.Report.Vulnerabilities)[0].Analysis = &cdx.VulnerabilityAnalysis{State: cdx.IASFalsePositive}

	e := gateWith(nil).Evaluate([]ComponentReport{report})
	if len(e.Findings) != 0 || len(e.Suppressed) != 1 || e.Suppressed[0].Statement.Source != ReportSource {
		t.Errorf("report analysis: %+v, want CVE-1 suppressed by the report itself", e)
	}
}

func TestLoadVEXRejectsOtherDocuments(t *testing.T) {
	for name, body := range map[string]string{
		"not json":     "not json",
		"other format": `{"spdxVersion":"SPDX-2.3"}`,
	} {
		if _, err := LoadVEX([]string{writeVEX(t, "doc.json", body)}); err == nil {
			t.Errorf("%s: LoadVEX() error = nil, want one", name)
		}
	}
	if _, err := LoadVEX([]string{filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Error("missing file: LoadVEX() error = nil, want one")
	}
}

// TestOpenVEXPurlMatching covers go-vex's purl semantics: a statement's
// purl without a version or qualifiers matches every version and
// qualifier of that package, but one with a version only that version.
func TestOpenVEXPurlMatching(t *testing.T) {
	doc := func(product string) string {
		return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","timestamp":"2026-01-01T00:00:00Z","statements":[
			{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"` + product + `"}],"status":"not_affected","justification":"component_not_present"}]}`
	}
	report := directReport(pkgA)

	for product, wantExempt := range map[string]bool{
		"pkg:apk/alpine/openssl":          true,  // any version
		"pkg:apk/alpine/openssl@3.1.0-r0": true,  // same version, report has extra qualifiers
		"pkg:apk/alpine/openssl@3.0.0-r0": false, // another version
		"pkg:apk/alpine/zlib":             false, // another package
	} {
		e := gateWith(loadVEX(t, doc(product))).Evaluate([]ComponentReport{report})
		if got := len(e.Suppressed) == 1; got != wantExempt {
			t.Errorf("product %s: exempt = %v, want %v", product, got, wantExempt)
		}
	}
}

// TestCycloneDXVEXEscapedBOMLink covers a BOM-Link whose bom-ref needed
// percent-encoding: it's unescaped before being looked up.
func TestCycloneDXVEXEscapedBOMLink(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
		"components":[{"bom-ref":"openssl@3.1","type":"library","name":"openssl","purl":"pkg:apk/alpine/openssl@3.1.0-r0"}],
		"vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected"},
			"affects":[{"ref":"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#openssl%403.1"}]}]}`

	if e := gateWith(loadVEX(t, doc)).Evaluate([]ComponentReport{directReport(pkgA)}); len(e.Suppressed) != 1 {
		t.Errorf("escaped BOM-Link: %+v, want CVE-1 suppressed", e)
	}
}
