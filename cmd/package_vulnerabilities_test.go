package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/security"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// writeVulnerabilityReportFixture writes component's vulnerability
// report (as "bomify security scan" itself would have, via
// security.NewReport/WriteReport) and returns the exact bytes landed on
// disk, trimmed of surrounding whitespace, for a test to compare
// (semantically — see jsonEqual, since "package vulnerabilities"
// re-indents each element to nest it under the array) against one
// element of "package vulnerabilities"' JSON array output.
func writeVulnerabilityReportFixture(t *testing.T, baseDir string, component cdx.Component, vulnID string) []byte {
	t.Helper()

	result := pluginlib.SecurityResult{
		Vulnerabilities: []cdx.Vulnerability{
			{ID: vulnID, Affects: &[]cdx.Affects{{Ref: component.PackageURL}}},
		},
	}
	report := security.NewReport(component, result, "", time.Time{})

	path, err := security.WriteReport(baseDir, security.ComponentReport{Component: component, Scanner: "grype", Report: report})
	if err != nil {
		t.Fatalf("WriteReport: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written report: %v", err)
	}
	return bytes.TrimSpace(data)
}

// runPackageVulnerabilitiesCmd runs "bomify package vulnerabilities
// <tag> [extraArgs...]" against baseDir, returning its stdout and error.
func runPackageVulnerabilitiesCmd(t *testing.T, baseDir, tag string, extraArgs ...string) (string, error) {
	t.Helper()

	origDataDir := dataDir
	t.Cleanup(func() { dataDir = origDataDir })
	dataDir = ""

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	args := append([]string{"--data-dir", baseDir, "package", "vulnerabilities", tag}, extraArgs...)
	root.SetArgs(args)

	err = root.Execute()
	return stdout.String(), err
}

// parseReportList parses out — "package vulnerabilities"' stdout — as a
// JSON array (the whole point of the format: it must be one value "jq"
// can consume directly), failing the test if it isn't one, and returns
// each element's own raw bytes for comparison.
func parseReportList(t *testing.T, out string) []json.RawMessage {
	t.Helper()

	var list []json.RawMessage
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("output is not a valid JSON array: %v\noutput:\n%s", err, out)
	}
	return list
}

// jsonEqual reports whether a and b decode to the same JSON value,
// ignoring formatting differences (writeReportList re-indents each
// report to nest it under the array, so a byte-for-byte comparison
// against the on-disk fixture would fail even for identical content).
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()

	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("unmarshal %s: %v", a, err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	return reflect.DeepEqual(av, bv)
}

// TestPackageVulnerabilitiesListsReports covers the default, no
// "--purl" case: every component the SBOM describes that has a local
// vulnerability report gets it included (content unchanged, formatting
// re-indented to nest under the array — see TestWriteReportListIndentsElements),
// in the SBOM's own order; a component with no report (never scanned)
// is silently skipped rather than erroring.
func TestPackageVulnerabilitiesListsReports(t *testing.T) {
	baseDir := newDataDir(t)

	componentA := cdx.Component{Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	componentB := cdx.Component{Name: "b", Version: "1.0", PackageURL: "pkg:generic/b@1.0"}
	componentC := cdx.Component{Name: "c", Version: "1.0", PackageURL: "pkg:generic/c@1.0"}

	writePackage(t, baseDir, "myapp:latest", componentA, componentB, componentC)

	reportA := writeVulnerabilityReportFixture(t, baseDir, componentA, "CVE-A")
	reportB := writeVulnerabilityReportFixture(t, baseDir, componentB, "CVE-B")
	// componentC deliberately gets no report.

	out, err := runPackageVulnerabilitiesCmd(t, baseDir, "myapp:latest")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	list := parseReportList(t, out)
	if len(list) != 2 {
		t.Fatalf("got %d reports, want 2 (componentC was never scanned):\n%s", len(list), out)
	}
	if !jsonEqual(t, list[0], reportA) {
		t.Errorf("report 0 = %s, want componentA's report (SBOM order)", list[0])
	}
	if !jsonEqual(t, list[1], reportB) {
		t.Errorf("report 1 = %s, want componentB's report (SBOM order)", list[1])
	}
}

// TestPackageVulnerabilitiesFiltersByPurl covers "--purl", repeated:
// only the named components' reports are included, and a --purl naming
// no component in the SBOM is reported but doesn't fail the command.
func TestPackageVulnerabilitiesFiltersByPurl(t *testing.T) {
	baseDir := newDataDir(t)

	componentA := cdx.Component{Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	componentB := cdx.Component{Name: "b", Version: "1.0", PackageURL: "pkg:generic/b@1.0"}

	writePackage(t, baseDir, "myapp:latest", componentA, componentB)

	reportA := writeVulnerabilityReportFixture(t, baseDir, componentA, "CVE-A")
	writeVulnerabilityReportFixture(t, baseDir, componentB, "CVE-B")

	out, err := runPackageVulnerabilitiesCmd(t, baseDir, "myapp:latest",
		"--purl", componentA.PackageURL,
		"--purl", "pkg:generic/nonexistent@1.0",
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	list := parseReportList(t, out)
	if len(list) != 1 {
		t.Fatalf("got %d reports, want 1:\n%s", len(list), out)
	}
	if !jsonEqual(t, list[0], reportA) {
		t.Errorf("report 0 = %s, want componentA's report", list[0])
	}
}

// TestPackageVulnerabilitiesDedupesRepeatedPurl covers a purl the SBOM
// lists more than once: its report is included only once.
func TestPackageVulnerabilitiesDedupesRepeatedPurl(t *testing.T) {
	baseDir := newDataDir(t)

	component := cdx.Component{Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	writePackage(t, baseDir, "myapp:latest", component, component)

	writeVulnerabilityReportFixture(t, baseDir, component, "CVE-A")

	out, err := runPackageVulnerabilitiesCmd(t, baseDir, "myapp:latest")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	list := parseReportList(t, out)
	if len(list) != 1 {
		t.Errorf("got %d reports, want 1 (purl listed twice in the sbom):\n%s", len(list), out)
	}
}

// TestPackageVulnerabilitiesEmptyList covers a package with no
// vulnerability reports at all: the output must still be a valid
// (empty) JSON array, not blank output or an error.
func TestPackageVulnerabilitiesEmptyList(t *testing.T) {
	baseDir := newDataDir(t)

	component := cdx.Component{Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	writePackage(t, baseDir, "myapp:latest", component)

	out, err := runPackageVulnerabilitiesCmd(t, baseDir, "myapp:latest")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	list := parseReportList(t, out)
	if len(list) != 0 {
		t.Errorf("got %d reports, want 0:\n%s", len(list), out)
	}
}

// TestWriteReportListIndentsElements covers the exact formatting: the
// root brackets sit at column 0, and every element — its own braces
// included — nests two spaces per level under it, regardless of how it
// was formatted going in.
func TestWriteReportListIndentsElements(t *testing.T) {
	reports := [][]byte{
		[]byte("{\n \"a\": 1\n}"),
		[]byte(`{"b":2}`),
	}

	var buf bytes.Buffer
	if err := writeReportList(&buf, reports); err != nil {
		t.Fatalf("writeReportList: %v", err)
	}

	want := "[\n  {\n    \"a\": 1\n  },\n  {\n    \"b\": 2\n  }\n]\n"
	if buf.String() != want {
		t.Errorf("writeReportList() =\n%q\nwant:\n%q", buf.String(), want)
	}
}
