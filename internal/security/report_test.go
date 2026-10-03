package security

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/layout"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// reportOf is component's report by scanner, with one vulnerability id.
func reportOf(scanner, id string) ComponentReport {
	result := pluginlib.SecurityResult{Vulnerabilities: []cdx.Vulnerability{{ID: id, Affects: &[]cdx.Affects{{Ref: testComponent.PackageURL}}}}}
	return ComponentReport{Component: testComponent, Scanner: scanner, Report: NewReport(testComponent, result, scanner, time.Now())}
}

// TestReportsArePerScanner writes two scanners' reports of one component,
// then rescans with one of them: each replaces only its own.
func TestReportsArePerScanner(t *testing.T) {
	baseDir := t.TempDir()
	purlHash := layout.PurlHash(testComponent.PackageURL)

	for _, r := range []ComponentReport{reportOf("trivy", "CVE-TRIVY"), reportOf("grype", "CVE-GRYPE-OLD"), reportOf("grype", "CVE-GRYPE")} {
		if _, err := WriteReport(baseDir, r); err != nil {
			t.Fatalf("WriteReport(%s): %v", r.Scanner, err)
		}
	}

	// Neither an in-flight write's temp file nor a stray file is a report.
	for _, name := range []string{".tmp-123", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(layout.ComponentReports(baseDir, purlHash), name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	stored, err := ReadReports(baseDir, purlHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || stored[0].Scanner != "grype" || stored[1].Scanner != "trivy" {
		t.Fatalf("ReadReports = %+v, want grype then trivy", stored)
	}
	if want := layout.Report(baseDir, purlHash, "grype"); stored[0].Path != want {
		t.Errorf("grype's path = %s, want %s", stored[0].Path, want)
	}
	for scanner, want := range map[string]string{"grype": "CVE-GRYPE", "trivy": "CVE-TRIVY"} {
		report, err := ReadReport(baseDir, purlHash, scanner)
		if err != nil {
			t.Fatal(err)
		}
		if got := (*report.Vulnerabilities)[0].ID; got != want {
			t.Errorf("%s's report has %s, want %s", scanner, got, want)
		}
	}

	if stored, err := ReadReports(baseDir, layout.PurlHash("pkg:generic/unscanned@1.0")); err != nil || len(stored) != 0 {
		t.Errorf("ReadReports of an unscanned component = %+v, %v; want none", stored, err)
	}
}

func TestWriteReportNeedsAUsableScanner(t *testing.T) {
	for _, scanner := range []string{"", "../escape", "a/b"} {
		r := reportOf("grype", "CVE-1")
		r.Scanner = scanner
		if _, err := WriteReport(t.TempDir(), r); err == nil {
			t.Errorf("WriteReport with scanner %q: nil, want an error", scanner)
		}
	}
}
