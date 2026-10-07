package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// buildFakeSecurityPluginBinary installs the fake plugin as
// bomify-plugin-<scanType> into baseDir's plugins directory, for
// plugin.Find to discover there.
func buildFakeSecurityPluginBinary(t *testing.T, baseDir, scanType string) {
	t.Helper()
	testutil.InstallFakePlugin(t, layout.Plugins(baseDir), scanType)
}

// writeResponsesFile writes responses (purl -> raw SecurityResult object
// JSON, e.g. `{"vulnerabilities":[...],"components":[...]}`) to a temp
// file and points FAKESECURITY_RESPONSES_FILE at it, so the fake
// security plugin reports exactly what the test expects for each
// component it's asked to scan — "affects" included, exactly as a real
// plugin would set it itself.
func writeResponsesFile(t *testing.T, responses map[string]string) {
	t.Helper()

	raw := map[string]json.RawMessage{}
	for purl, body := range responses {
		raw[purl] = json.RawMessage(body)
	}

	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal responses: %v", err)
	}

	path := filepath.Join(t.TempDir(), "responses.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write responses file: %v", err)
	}

	t.Setenv("FAKESECURITY_RESPONSES_FILE", path)
}

// writePackage records a minimal CycloneDX SBOM naming components (one
// purl each) as a built package in baseDir, tagged tag — exactly the
// bookkeeping "bomify build --tag" leaves behind, minus the pulled
// layers "bomify security scan" never looks at.
func writePackage(t *testing.T, baseDir, tag string, components ...cdx.Component) {
	t.Helper()

	bom := struct {
		BOMFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		Version     int             `json:"version"`
		Components  []cdx.Component `json:"components"`
	}{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  components,
	}

	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal sbom: %v", err)
	}

	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	sbomHash, _, err := build.RecordManifest(baseDir, path)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	if err := build.UpdateRepositories(baseDir, []string{tag}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}
}

// runSecurityScanCmd runs "bomify security scan <scanType> <tag>"
// against baseDir, returning its stdout and error.
func runSecurityScanCmd(t *testing.T, baseDir, scanType, tag string) (string, error) {
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
	root.SetArgs([]string{"--data-dir", baseDir, "security", "scan", scanType, tag})

	err = root.Execute()
	return stdout.String(), err
}

// readReport reads component's vulnerability report from baseDir,
// failing the test if there isn't one.
func readReport(t *testing.T, baseDir string, component cdx.Component) *cdx.BOM {
	t.Helper()

	report, err := sbom.Load(layout.Report(baseDir, layout.PurlHash(component.PackageURL), "grype"))
	if err != nil {
		t.Fatalf("read report for %s: %v", component.PackageURL, err)
	}
	return report
}

// usePlugin installs a freshly built fake security plugin named
// bomify-plugin-<scanType> into baseDir.
func usePlugin(t *testing.T, baseDir, scanType string) {
	t.Helper()

	buildFakeSecurityPluginBinary(t, baseDir, scanType)
}

// TestSecurityScanWritesOneReportPerComponent covers components scanned
// directly (no unpacking): each gets its own report, keyed by its purl
// hash, with the component itself as the report's metadata component and
// no top-level components of its own. A vulnerability two components
// share is reported in both, never merged across them.
func TestSecurityScanWritesOneReportPerComponent(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")

	componentA := cdx.Component{BOMRef: "ref-a", Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	componentB := cdx.Component{BOMRef: "ref-b", Name: "b", Version: "1.0", PackageURL: "pkg:generic/b@1.0"}

	writeResponsesFile(t, map[string]string{
		"pkg:generic/a@1.0": `{"vulnerabilities":[
			{"bom-ref":"CVE-SHARED","id":"CVE-SHARED","affects":[{"ref":"pkg:generic/a@1.0"}]},
			{"bom-ref":"CVE-A-ONLY","id":"CVE-A-ONLY","affects":[{"ref":"pkg:generic/a@1.0"}]}
		]}`,
		"pkg:generic/b@1.0": `{"vulnerabilities":[
			{"bom-ref":"CVE-SHARED","id":"CVE-SHARED","affects":[{"ref":"pkg:generic/b@1.0"}]}
		]}`,
	})

	writePackage(t, baseDir, "myapp:latest", componentA, componentB)

	if _, err := runSecurityScanCmd(t, baseDir, "grype", "myapp:latest"); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	for _, tc := range []struct {
		component cdx.Component
		wantIDs   []string
	}{
		{componentA, []string{"CVE-SHARED", "CVE-A-ONLY"}},
		{componentB, []string{"CVE-SHARED"}},
	} {
		report := readReport(t, baseDir, tc.component)

		if report.Metadata == nil || report.Metadata.Component == nil {
			t.Fatalf("%s report has no metadata component", tc.component.Name)
		}
		subject := report.Metadata.Component
		if subject.PackageURL != tc.component.PackageURL || subject.Name != tc.component.Name {
			t.Errorf("%s report metadata component = %+v, want the scanned component", tc.component.Name, subject)
		}
		// Shared across packages, so keyed by purl rather than whatever
		// bom-ref this one SBOM happened to assign.
		if subject.BOMRef != tc.component.PackageURL {
			t.Errorf("%s report metadata component bom-ref = %q, want its purl", tc.component.Name, subject.BOMRef)
		}
		if report.Components != nil && len(*report.Components) != 0 {
			t.Errorf("%s report components = %+v, want none for a directly scanned component", tc.component.Name, *report.Components)
		}

		if report.Vulnerabilities == nil || len(*report.Vulnerabilities) != len(tc.wantIDs) {
			t.Fatalf("%s report vulnerabilities = %+v, want %v", tc.component.Name, report.Vulnerabilities, tc.wantIDs)
		}
		for i, v := range *report.Vulnerabilities {
			if v.ID != tc.wantIDs[i] {
				t.Errorf("%s report vulnerability %d = %q, want %q", tc.component.Name, i, v.ID, tc.wantIDs[i])
			}
			if v.Affects == nil || len(*v.Affects) != 1 || (*v.Affects)[0].Ref != tc.component.PackageURL {
				t.Errorf("%s report %s.Affects = %+v, want only its own purl", tc.component.Name, v.ID, v.Affects)
			}
		}
	}
}

// TestSecurityScanImageReportNestsUnpackedComponents covers a plugin
// that had to unpack a component (e.g. cataloging a container image) to
// scan it: the image is the report's metadata component, the affected
// pieces the plugin found are the report's top-level components (an
// unpacked piece nothing was found in, like musl here, is left out),
// and every vulnerability's "affects" — exactly as the plugin reported
// it — references the specific piece, never the image itself.
func TestSecurityScanImageReportNestsUnpackedComponents(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")

	image := cdx.Component{BOMRef: "image-ref", Type: cdx.ComponentTypeContainer, Name: "myimage", Version: "1.0", PackageURL: "pkg:oci/myimage@1.0"}

	writeResponsesFile(t, map[string]string{
		"pkg:oci/myimage@1.0": `{
			"vulnerabilities": [
				{"bom-ref":"CVE-NESTED","id":"CVE-NESTED","affects":[{"ref":"pkg:npm/lodash@4.17.15"}]}
			],
			"components": [
				{"bom-ref":"pkg:npm/lodash@4.17.15","type":"library","name":"lodash","version":"4.17.15","purl":"pkg:npm/lodash@4.17.15"},
				{"bom-ref":"pkg:apk/musl@1.2.3","type":"library","name":"musl","version":"1.2.3","purl":"pkg:apk/musl@1.2.3"}
			]
		}`,
	})

	writePackage(t, baseDir, "myapp:latest", image)

	if _, err := runSecurityScanCmd(t, baseDir, "grype", "myapp:latest"); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	report := readReport(t, baseDir, image)

	if report.Metadata == nil || report.Metadata.Component == nil || report.Metadata.Component.PackageURL != image.PackageURL {
		t.Fatalf("report metadata = %+v, want the image as its component", report.Metadata)
	}
	if report.Metadata.Component.Components != nil {
		t.Errorf("report metadata component has nested components %+v, want them at the report's top level instead", *report.Metadata.Component.Components)
	}

	if report.Components == nil || len(*report.Components) != 1 {
		t.Fatalf("report components = %+v, want 1 (lodash only; musl is unaffected)", report.Components)
	}
	if (*report.Components)[0].BOMRef != "pkg:npm/lodash@4.17.15" {
		t.Errorf("report components = %+v, want lodash", *report.Components)
	}

	if report.Vulnerabilities == nil || len(*report.Vulnerabilities) != 1 {
		t.Fatalf("report vulnerabilities = %+v, want exactly 1", report.Vulnerabilities)
	}
	v := (*report.Vulnerabilities)[0]
	if v.Affects == nil || len(*v.Affects) != 1 || (*v.Affects)[0].Ref != "pkg:npm/lodash@4.17.15" {
		t.Errorf("CVE-NESTED.Affects = %+v, want a single entry for the nested lodash component, never the image itself", v.Affects)
	}
}

// TestSecurityScanSharesReportsAcrossPackages covers a component
// described by two packages: both resolve to the same report, and
// scanning either one refreshes it for both.
func TestSecurityScanSharesReportsAcrossPackages(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")

	// The same purl, described slightly differently by each package's
	// SBOM — the report must not depend on which one scanned it.
	sharedInApp := cdx.Component{BOMRef: "app-shared", Name: "shared", Version: "1.0", PackageURL: "pkg:generic/shared@1.0"}
	sharedInOther := cdx.Component{BOMRef: "other-shared", Name: "shared", Version: "1.0", PackageURL: "pkg:generic/shared@1.0"}
	appOnly := cdx.Component{Name: "app-only", Version: "1.0", PackageURL: "pkg:generic/app-only@1.0"}

	writePackage(t, baseDir, "app:1", sharedInApp, appOnly)
	writePackage(t, baseDir, "other:1", sharedInOther)

	writeResponsesFile(t, map[string]string{
		"pkg:generic/shared@1.0": `{"vulnerabilities":[{"bom-ref":"CVE-OLD","id":"CVE-OLD","affects":[{"ref":"pkg:generic/shared@1.0"}]}]}`,
	})
	if _, err := runSecurityScanCmd(t, baseDir, "grype", "app:1"); err != nil {
		t.Fatalf("scan app:1: %v", err)
	}

	// Newer vulnerability data, scanned through the other package.
	writeResponsesFile(t, map[string]string{
		"pkg:generic/shared@1.0": `{"vulnerabilities":[{"bom-ref":"CVE-NEW","id":"CVE-NEW","affects":[{"ref":"pkg:generic/shared@1.0"}]}]}`,
	})
	if _, err := runSecurityScanCmd(t, baseDir, "grype", "other:1"); err != nil {
		t.Fatalf("scan other:1: %v", err)
	}

	entries, err := os.ReadDir(layout.Reports(baseDir))
	if err != nil {
		t.Fatalf("read reports dir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("reports dir has %d entries, want 2 (shared and app-only, the shared one written once)", len(entries))
	}

	report := readReport(t, baseDir, sharedInApp)
	if report.Vulnerabilities == nil || len(*report.Vulnerabilities) != 1 || (*report.Vulnerabilities)[0].ID != "CVE-NEW" {
		t.Errorf("shared report vulnerabilities = %+v, want the latest scan's CVE-NEW only", report.Vulnerabilities)
	}
	if report.Metadata.Component.BOMRef != sharedInApp.PackageURL {
		t.Errorf("shared report metadata component bom-ref = %q, want its purl, not either package's own bom-ref", report.Metadata.Component.BOMRef)
	}
}

func TestSecurityScanSkipsComponentsUnsupportedByPlugin(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")
	// This plugin only supports oci — the npm component below must be
	// skipped rather than sent to "security scan", and gets no report.
	t.Setenv("FAKESECURITY_SUPPORTED_COMPONENTS", `{"types":{"oci":"purl"},"scans":["sca"]}`)

	componentOCI := cdx.Component{Name: "supported", PackageURL: "pkg:oci/supported@1.0"}
	componentNPM := cdx.Component{Name: "unsupported", PackageURL: "pkg:npm/unsupported@1.0"}

	writeResponsesFile(t, map[string]string{
		"pkg:oci/supported@1.0":   `{"vulnerabilities":[{"bom-ref":"CVE-OCI","id":"CVE-OCI","affects":[{"ref":"pkg:oci/supported@1.0"}]}]}`,
		"pkg:npm/unsupported@1.0": `{"vulnerabilities":[{"bom-ref":"CVE-NPM","id":"CVE-NPM","affects":[{"ref":"pkg:npm/unsupported@1.0"}]}]}`,
	})

	writePackage(t, baseDir, "myapp:latest", componentOCI, componentNPM)

	if _, err := runSecurityScanCmd(t, baseDir, "grype", "myapp:latest"); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	report := readReport(t, baseDir, componentOCI)
	if report.Vulnerabilities == nil || len(*report.Vulnerabilities) != 1 || (*report.Vulnerabilities)[0].ID != "CVE-OCI" {
		t.Errorf("oci report vulnerabilities = %+v, want CVE-OCI only", report.Vulnerabilities)
	}

	if _, err := os.Stat(layout.Report(baseDir, layout.PurlHash(componentNPM.PackageURL), "grype")); !os.IsNotExist(err) {
		t.Errorf("unsupported component has a report (stat err = %v), want none", err)
	}
}

func TestSecurityScanFailsWhenSupportedComponentsFails(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")
	t.Setenv("FAKESECURITY_SUPPORTED_COMPONENTS_FAIL", "1")

	writePackage(t, baseDir, "myapp:latest", cdx.Component{Name: "a", PackageURL: "pkg:oci/a@1.0"})

	if _, err := runSecurityScanCmd(t, baseDir, "grype", "myapp:latest"); err == nil {
		t.Fatal("Execute() error = nil, want an error when the plugin's required supported-components subcommand fails")
	}
}

func TestSecurityScanPropagatesComponentFailure(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")

	writePackage(t, baseDir, "myapp:latest", cdx.Component{Name: "broken", PackageURL: "pkg:generic/fail-me@1.0"})

	if _, err := runSecurityScanCmd(t, baseDir, "grype", "myapp:latest"); err == nil {
		t.Fatal("Execute() error = nil, want an error from the failing component scan")
	}
}

func TestSecurityScanUnknownPackage(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")

	if _, err := runSecurityScanCmd(t, baseDir, "grype", "missing:latest"); err == nil {
		t.Fatal("Execute() error = nil, want an error for a package that doesn't exist locally")
	}
}

func TestSecurityScanMissingPlugin(t *testing.T) {
	baseDir := newDataDir(t)

	writePackage(t, baseDir, "myapp:latest", cdx.Component{Name: "a", PackageURL: "pkg:oci/a@1.0"})

	if _, err := runSecurityScanCmd(t, baseDir, "does-not-exist", "myapp:latest"); err == nil {
		t.Fatal("Execute() error = nil, want an error for a missing plugin")
	}
}

// TestSecurityScanKeepsEveryScannersReport scans one package with two
// scanners, then the first again: each keeps its own report, and
// "package vulnerabilities" prints both.
func TestSecurityScanKeepsEveryScannersReport(t *testing.T) {
	baseDir := newDataDir(t)
	usePlugin(t, baseDir, "grype")
	usePlugin(t, baseDir, "trivy")
	component := cdx.Component{Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	writePackage(t, baseDir, "myapp:latest", component)

	for _, scanner := range []string{"grype", "trivy", "grype"} {
		if _, err := runSecurityScanCmd(t, baseDir, scanner, "myapp:latest"); err != nil {
			t.Fatalf("scan with %s: %v", scanner, err)
		}
	}

	purlHash := layout.PurlHash(component.PackageURL)
	for _, scanner := range []string{"grype", "trivy"} {
		report, err := sbom.Load(layout.Report(baseDir, purlHash, scanner))
		if err != nil {
			t.Fatalf("%s's report: %v", scanner, err)
		}
		if tools := report.Metadata.Tools; tools == nil || tools.Components == nil || (*tools.Components)[0].Name != scanner {
			t.Errorf("%s's report doesn't name it as its scanner: %+v", scanner, tools)
		}
	}

	out, err := runRootCmd(t, baseDir, "package", "vulnerabilities", "myapp:latest")
	if err != nil {
		t.Fatalf("package vulnerabilities: %v", err)
	}
	var printed []json.RawMessage
	if err := json.Unmarshal([]byte(out), &printed); err != nil || len(printed) != 2 {
		t.Errorf("package vulnerabilities printed %d reports (%v), want one per scanner:\n%s", len(printed), err, out)
	}
}
