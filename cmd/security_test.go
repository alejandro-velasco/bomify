package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// buildFakeSecurityPluginBinary builds cmd/testdata/fakesecurityplugin as
// bomify-plugin-<scanType>[.exe] into a fresh temp directory and returns
// that directory, so the caller can put it on PATH for plugin.Find to
// discover.
func buildFakeSecurityPluginBinary(t *testing.T, scanType string) string {
	t.Helper()

	dir := t.TempDir()
	bin := filepath.Join(dir, "bomify-plugin-"+scanType)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	build := exec.Command("go", "build", "-o", bin, "./testdata/fakesecurityplugin")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake security plugin: %v\n%s", err, out)
	}

	return dir
}

// writeResponsesFile writes responses (purl -> raw vulnerability array
// JSON) to a temp file and points FAKESECURITY_RESPONSES_FILE at it, so
// the fake security plugin reports exactly what the test expects for
// each component it's asked to scan.
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

// writeSBOMFile writes a minimal CycloneDX SBOM naming components (one
// purl each) to a temp file and returns its path.
func writeSBOMFile(t *testing.T, components ...cdx.Component) string {
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

	return path
}

func TestSecurityScanMergesVulnerabilitiesAcrossComponents(t *testing.T) {
	dir := buildFakeSecurityPluginBinary(t, "grype")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	componentA := cdx.Component{BOMRef: "ref-a", Name: "a", PackageURL: "pkg:oci/a@1.0"}
	componentB := cdx.Component{BOMRef: "ref-b", Name: "b", PackageURL: "pkg:oci/b@1.0"}
	// componentC has no bom-ref of its own, so its Affects must fall back
	// to its purl.
	componentC := cdx.Component{Name: "c", PackageURL: "pkg:oci/c@1.0"}

	writeResponsesFile(t, map[string]string{
		// The same vulnerability, reported by both A and B, must be
		// merged into a single entry naming both in "affects".
		"pkg:oci/a@1.0": `[{"bom-ref":"CVE-SHARED","id":"CVE-SHARED"},{"bom-ref":"CVE-A-ONLY","id":"CVE-A-ONLY"}]`,
		"pkg:oci/b@1.0": `[{"bom-ref":"CVE-SHARED","id":"CVE-SHARED"}]`,
		"pkg:oci/c@1.0": `[{"id":"CVE-NO-BOMREF"}]`,
	})

	sbomPath := writeSBOMFile(t, componentA, componentB, componentC)

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"security", "scan", "grype", sbomPath})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}

	var got cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}

	if got.Vulnerabilities == nil {
		t.Fatal("output has no vulnerabilities")
	}
	byRef := map[string]cdx.Vulnerability{}
	for _, v := range *got.Vulnerabilities {
		byRef[v.BOMRef] = v
	}

	// Exactly 3 distinct entries: CVE-SHARED (merged), CVE-A-ONLY, and
	// the no-bom-ref one — never 4, which would mean CVE-SHARED wasn't
	// deduplicated.
	if len(*got.Vulnerabilities) != 3 {
		t.Fatalf("got %d vulnerabilities, want 3: %+v", len(*got.Vulnerabilities), *got.Vulnerabilities)
	}

	shared, ok := byRef["CVE-SHARED"]
	if !ok {
		t.Fatal("CVE-SHARED missing from output")
	}
	if shared.Affects == nil || len(*shared.Affects) != 2 {
		t.Fatalf("CVE-SHARED.Affects = %+v, want 2 entries (both components)", shared.Affects)
	}
	affectedRefs := map[string]bool{}
	for _, a := range *shared.Affects {
		affectedRefs[a.Ref] = true
	}
	if !affectedRefs["ref-a"] || !affectedRefs["ref-b"] {
		t.Errorf("CVE-SHARED.Affects = %+v, want refs ref-a and ref-b", *shared.Affects)
	}

	aOnly, ok := byRef["CVE-A-ONLY"]
	if !ok {
		t.Fatal("CVE-A-ONLY missing from output")
	}
	if aOnly.Affects == nil || len(*aOnly.Affects) != 1 || (*aOnly.Affects)[0].Ref != "ref-a" {
		t.Errorf("CVE-A-ONLY.Affects = %+v, want a single entry for ref-a", aOnly.Affects)
	}

	// componentC has no bom-ref, so its vulnerability's Affects must name
	// it by purl instead.
	found := false
	for _, v := range *got.Vulnerabilities {
		if v.ID == "CVE-NO-BOMREF" {
			found = true
			if v.Affects == nil || len(*v.Affects) != 1 || (*v.Affects)[0].Ref != "pkg:oci/c@1.0" {
				t.Errorf("CVE-NO-BOMREF.Affects = %+v, want a single entry for pkg:oci/c@1.0 (componentC's purl, since it has no bom-ref)", v.Affects)
			}
		}
	}
	if !found {
		t.Error("CVE-NO-BOMREF missing from output")
	}
}

func TestSecurityScanSkipsComponentsUnsupportedByPlugin(t *testing.T) {
	dir := buildFakeSecurityPluginBinary(t, "grype")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// This plugin only supports oci — the npm component below must be
	// skipped rather than sent to "security scan".
	t.Setenv("FAKESECURITY_SUPPORTED_COMPONENTS", `{"types":["oci"],"scans":["sca"]}`)

	componentOCI := cdx.Component{BOMRef: "ref-oci", Name: "supported", PackageURL: "pkg:oci/supported@1.0"}
	componentNPM := cdx.Component{BOMRef: "ref-npm", Name: "unsupported", PackageURL: "pkg:npm/unsupported@1.0"}

	writeResponsesFile(t, map[string]string{
		"pkg:oci/supported@1.0":   `[{"bom-ref":"CVE-OCI","id":"CVE-OCI"}]`,
		"pkg:npm/unsupported@1.0": `[{"bom-ref":"CVE-NPM","id":"CVE-NPM"}]`,
	})

	sbomPath := writeSBOMFile(t, componentOCI, componentNPM)

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"security", "scan", "grype", sbomPath})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}

	var got cdx.BOM
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, stdout.String())
	}

	if got.Vulnerabilities == nil || len(*got.Vulnerabilities) != 1 {
		t.Fatalf("got vulnerabilities = %+v, want exactly 1 (npm component skipped)", got.Vulnerabilities)
	}
	if (*got.Vulnerabilities)[0].ID != "CVE-OCI" {
		t.Errorf("vulnerability = %+v, want CVE-OCI only", (*got.Vulnerabilities)[0])
	}
}

func TestSecurityScanFailsWhenSupportedComponentsFails(t *testing.T) {
	dir := buildFakeSecurityPluginBinary(t, "grype")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKESECURITY_SUPPORTED_COMPONENTS_FAIL", "1")

	sbomPath := writeSBOMFile(t, cdx.Component{Name: "a", PackageURL: "pkg:oci/a@1.0"})

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"security", "scan", "grype", sbomPath})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want an error when the plugin's required supported-components subcommand fails")
	}
}

func TestSecurityScanPropagatesComponentFailure(t *testing.T) {
	dir := buildFakeSecurityPluginBinary(t, "grype")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	sbomPath := writeSBOMFile(t, cdx.Component{Name: "broken", PackageURL: "pkg:generic/fail-me@1.0"})

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"security", "scan", "grype", sbomPath})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want an error from the failing component scan")
	}
}

func TestSecurityScanMissingPlugin(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"security", "scan", "does-not-exist", "sbom.cdx.json"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want an error for a missing plugin")
	}
}
