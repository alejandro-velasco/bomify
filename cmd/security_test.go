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

	// bomify itself never sets or overwrites "affects" — the plugin does,
	// and for a plain (non-image) scan the only thing it has to name is
	// the purl it was given, so that's what each canned response's
	// "affects" points at here, exactly as a real plugin would.
	componentA := cdx.Component{BOMRef: "ref-a", Name: "a", PackageURL: "pkg:oci/a@1.0"}
	componentB := cdx.Component{BOMRef: "ref-b", Name: "b", PackageURL: "pkg:oci/b@1.0"}

	writeResponsesFile(t, map[string]string{
		// The same vulnerability, reported by both A and B, must be
		// merged into a single entry combining both "affects" entries.
		"pkg:oci/a@1.0": `{"vulnerabilities":[
			{"bom-ref":"CVE-SHARED","id":"CVE-SHARED","affects":[{"ref":"pkg:oci/a@1.0"}]},
			{"bom-ref":"CVE-A-ONLY","id":"CVE-A-ONLY","affects":[{"ref":"pkg:oci/a@1.0"}]}
		]}`,
		"pkg:oci/b@1.0": `{"vulnerabilities":[
			{"bom-ref":"CVE-SHARED","id":"CVE-SHARED","affects":[{"ref":"pkg:oci/b@1.0"}]}
		]}`,
	})

	sbomPath := writeSBOMFile(t, componentA, componentB)

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

	// Exactly 2 distinct entries: CVE-SHARED (merged) and CVE-A-ONLY —
	// never 3, which would mean CVE-SHARED wasn't deduplicated.
	if len(*got.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2: %+v", len(*got.Vulnerabilities), *got.Vulnerabilities)
	}

	shared, ok := byRef["CVE-SHARED"]
	if !ok {
		t.Fatal("CVE-SHARED missing from output")
	}
	if shared.Affects == nil || len(*shared.Affects) != 2 {
		t.Fatalf("CVE-SHARED.Affects = %+v, want 2 entries (both components' purls)", shared.Affects)
	}
	affectedRefs := map[string]bool{}
	for _, a := range *shared.Affects {
		affectedRefs[a.Ref] = true
	}
	if !affectedRefs["pkg:oci/a@1.0"] || !affectedRefs["pkg:oci/b@1.0"] {
		t.Errorf("CVE-SHARED.Affects = %+v, want refs pkg:oci/a@1.0 and pkg:oci/b@1.0 (bomify must not rewrite what the plugin reported)", *shared.Affects)
	}

	aOnly, ok := byRef["CVE-A-ONLY"]
	if !ok {
		t.Fatal("CVE-A-ONLY missing from output")
	}
	if aOnly.Affects == nil || len(*aOnly.Affects) != 1 || (*aOnly.Affects)[0].Ref != "pkg:oci/a@1.0" {
		t.Errorf("CVE-A-ONLY.Affects = %+v, want a single entry for pkg:oci/a@1.0", aOnly.Affects)
	}
}

// TestSecurityScanEmbedsNestedComponentsFromImageScan covers a plugin
// that had to unpack a component (e.g. cataloging a container image) to
// scan it: bomify must embed the pieces it reported as that component's
// own nested components, and every vulnerability's "affects" — set by
// the plugin, exactly as reported — must reference the specific nested
// piece, never the top-level image component itself.
func TestSecurityScanEmbedsNestedComponentsFromImageScan(t *testing.T) {
	dir := buildFakeSecurityPluginBinary(t, "grype")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	image := cdx.Component{BOMRef: "image-ref", Name: "myimage", PackageURL: "pkg:oci/myimage@1.0"}

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

	sbomPath := writeSBOMFile(t, image)

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

	if got.Components == nil || len(*got.Components) != 1 {
		t.Fatalf("got.Components = %+v, want exactly the one top-level image component", got.Components)
	}
	imageComponent := (*got.Components)[0]
	if imageComponent.Components == nil || len(*imageComponent.Components) != 2 {
		t.Fatalf("image component's nested Components = %+v, want 2 (lodash and musl)", imageComponent.Components)
	}
	nestedRefs := map[string]bool{}
	for _, c := range *imageComponent.Components {
		nestedRefs[c.BOMRef] = true
	}
	if !nestedRefs["pkg:npm/lodash@4.17.15"] || !nestedRefs["pkg:apk/musl@1.2.3"] {
		t.Errorf("image component's nested Components = %+v, want lodash and musl", *imageComponent.Components)
	}

	if got.Vulnerabilities == nil || len(*got.Vulnerabilities) != 1 {
		t.Fatalf("got.Vulnerabilities = %+v, want exactly 1", got.Vulnerabilities)
	}
	v := (*got.Vulnerabilities)[0]
	if v.Affects == nil || len(*v.Affects) != 1 || (*v.Affects)[0].Ref != "pkg:npm/lodash@4.17.15" {
		t.Errorf("CVE-NESTED.Affects = %+v, want a single entry for the nested lodash component, never the image itself", v.Affects)
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
		"pkg:oci/supported@1.0":   `{"vulnerabilities":[{"bom-ref":"CVE-OCI","id":"CVE-OCI","affects":[{"ref":"pkg:oci/supported@1.0"}]}]}`,
		"pkg:npm/unsupported@1.0": `{"vulnerabilities":[{"bom-ref":"CVE-NPM","id":"CVE-NPM","affects":[{"ref":"pkg:npm/unsupported@1.0"}]}]}`,
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
