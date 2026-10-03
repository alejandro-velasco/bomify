package cmd

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/security"
)

// setUpGatedPackage installs the fake scanner and records myapp:latest,
// whose one component has one high and one low vulnerability.
func setUpGatedPackage(t *testing.T) (baseDir string, component cdx.Component) {
	t.Helper()

	baseDir = t.TempDir()
	usePlugin(t, baseDir, "grype")

	component = cdx.Component{Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	writeResponsesFile(t, map[string]string{
		"pkg:generic/a@1.0": `{"vulnerabilities":[
			{"id":"CVE-HIGH","ratings":[{"severity":"high","method":"CVSSv31"}],"affects":[{"ref":"pkg:generic/a@1.0"}]},
			{"id":"CVE-LOW","ratings":[{"severity":"low","method":"CVSSv31"}],"affects":[{"ref":"pkg:generic/a@1.0"}]}
		]}`,
	})
	writePackage(t, baseDir, "registry.example.com/team/myapp:latest", component)
	return baseDir, component
}

const gatedTag = "registry.example.com/team/myapp:latest"

func TestSecurityScanFailOn(t *testing.T) {
	baseDir, component := setUpGatedPackage(t)

	_, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "high")
	var gateErr *security.GateError
	if !errors.As(err, &gateErr) {
		t.Fatalf("--fail-on high: error = %v, want a gate failure", err)
	}
	if len(gateErr.Findings) != 1 || gateErr.Findings[0].ID != "CVE-HIGH" {
		t.Errorf("findings = %+v, want just CVE-HIGH", gateErr.Findings)
	}
	// Reports are written even when the gate fails.
	readReport(t, baseDir, component)

	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "critical"); err != nil {
		t.Errorf("--fail-on critical: error = %v, want none", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "high", "--ignore", "CVE-HIGH"); err != nil {
		t.Errorf("--ignore CVE-HIGH: error = %v, want none", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag); err != nil {
		t.Errorf("no gate: error = %v, want none", err)
	}
}

func TestSecurityScanAppliesPolicy(t *testing.T) {
	baseDir, _ := setUpGatedPackage(t)

	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--match", "registry.example.com/team", "--fail-on", "low"); err != nil {
		t.Fatalf("policy create: %v", err)
	}

	var gateErr *security.GateError
	_, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag)
	if !errors.As(err, &gateErr) || len(gateErr.Findings) != 2 {
		t.Fatalf("with rule: error = %v, want both vulnerabilities to fail it", err)
	}

	// An explicit --fail-on replaces the rule rather than combining with it.
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "critical"); err != nil {
		t.Errorf("--fail-on critical over a rule: error = %v, want none", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-gate"); err != nil {
		t.Errorf("--skip-gate: error = %v, want none", err)
	}
	// Only pull and load take --skip-scan: an explicit scan can't skip
	// itself.
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-scan"); err == nil {
		t.Error("security scan --skip-scan: error = nil, want an unknown-flag error")
	}
}

func TestSecurityScanGateFlagValidation(t *testing.T) {
	baseDir, _ := setUpGatedPackage(t)

	for _, args := range [][]string{
		{"--fail-on", "severe"},
		{"--fail-on", "high,low"},
		{"--ignore", "CVE-HIGH"},
		{"--ignore", "CVE-HIGH", "--fail-on", "unscanned"},
		{"--skip-gate", "--fail-on", "high"},
	} {
		if _, err := runRootCmd(t, baseDir, append([]string{"security", "scan", "grype", gatedTag}, args...)...); err == nil || errors.As(err, new(*security.GateError)) {
			t.Errorf("%v: error = %v, want a flag error", args, err)
		}
	}
}

func TestSecurityPolicyCreateListRemove(t *testing.T) {
	baseDir := t.TempDir()

	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--match", "registry.example.com/team", "--fail-on", "high"); err != nil {
		t.Fatalf("policy create: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype"); err != nil {
		t.Fatalf("policy create (catch-all): %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--fail-on", "severe"); err == nil {
		t.Error("policy create accepted an invalid --fail-on")
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--ignore", "CVE-1"); err == nil {
		t.Error("policy create accepted --ignore, which rules don't have")
	}

	out, err := runRootCmd(t, baseDir, "security", "policy", "list")
	if err != nil {
		t.Fatalf("policy list: %v", err)
	}
	for _, want := range []string{"MATCH", "registry.example.com/team", "high", "*", "-"} {
		if !strings.Contains(out, want) {
			t.Errorf("policy list output missing %q:\n%s", want, out)
		}
	}

	if _, err := runRootCmd(t, baseDir, "security", "policy", "remove", "--match", "registry.example.com/team"); err != nil {
		t.Fatalf("policy remove: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "remove", "--match", "registry.example.com/team"); err == nil {
		t.Error("policy remove of a missing rule succeeded")
	}
}

// writeOpenVEX writes an OpenVEX document stating CVE-HIGH doesn't
// affect pkg:generic/a@1.0, returning its path.
func writeOpenVEX(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "a.openvex.json")
	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","timestamp":"2026-01-01T00:00:00Z",
		"statements":[{"vulnerability":{"name":"CVE-HIGH"},"products":[{"@id":"pkg:generic/a@1.0"}],
		"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatalf("write VEX: %v", err)
	}
	return path
}

func TestSecurityScanVEX(t *testing.T) {
	baseDir, _ := setUpGatedPackage(t)
	vex := writeOpenVEX(t)

	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "high", "--vex", vex); err != nil {
		t.Errorf("--vex clearing CVE-HIGH: error = %v, want none", err)
	}
	// VEX only exempts what it names: CVE-LOW still fails a low bar.
	var gateErr *security.GateError
	_, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "low", "--vex", vex)
	if !errors.As(err, &gateErr) || len(gateErr.Findings) != 1 || gateErr.Findings[0].ID != "CVE-LOW" {
		t.Errorf("--fail-on low --vex: error = %v, want just CVE-LOW", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-gate", "--vex", vex); err == nil {
		t.Error("--skip-gate --vex: error = nil, want a flag error")
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "high", "--vex", filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing --vex file: error = nil, want one")
	}
}

func TestSecurityPolicyVEX(t *testing.T) {
	baseDir, _ := setUpGatedPackage(t)
	vex := writeOpenVEX(t)

	// Rules refer to stored documents by name, never by path.
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--fail-on", "high", "--vex", vex); err == nil {
		t.Error("policy create --vex <path>: error = nil, want an unknown-name error")
	}
	if _, err := runRootCmd(t, baseDir, "security", "vex", "add", "team", vex); err != nil {
		t.Fatalf("vex add: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--match", "registry.example.com/team", "--fail-on", "high", "--vex", "team"); err != nil {
		t.Fatalf("policy create --vex team: %v", err)
	}

	// The stored copy is what counts: the original can go away.
	if err := os.Remove(vex); err != nil {
		t.Fatalf("remove original: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag); err != nil {
		t.Errorf("rule with stored VEX: error = %v, want none", err)
	}
	// An explicit --fail-on replaces the rule's threshold, but its VEX
	// still applies.
	var gateErr *security.GateError
	_, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "low")
	if !errors.As(err, &gateErr) || len(gateErr.Findings) != 1 || gateErr.Findings[0].ID != "CVE-LOW" {
		t.Errorf("--fail-on low over a rule with VEX: error = %v, want just CVE-LOW", err)
	}

	out, err := runRootCmd(t, baseDir, "security", "policy", "list")
	if err != nil || !strings.Contains(out, "team") {
		t.Errorf("policy list = %q, %v; want the VEX name listed", out, err)
	}

	// A document a rule still uses can't be removed.
	if _, err := runRootCmd(t, baseDir, "security", "vex", "remove", "team"); err == nil {
		t.Error("vex remove of a document in use: error = nil, want one")
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "remove", "--match", "registry.example.com/team"); err != nil {
		t.Fatalf("policy remove: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "vex", "remove", "team"); err != nil {
		t.Errorf("vex remove: %v", err)
	}
}

func TestSecurityVEXAddListRemove(t *testing.T) {
	baseDir := t.TempDir()
	vex := writeOpenVEX(t)

	if _, err := runRootCmd(t, baseDir, "security", "vex", "add", "team", vex); err != nil {
		t.Fatalf("vex add: %v", err)
	}
	out, err := runRootCmd(t, baseDir, "security", "vex", "list")
	if err != nil || !strings.Contains(out, "team") || !strings.Contains(out, vex) {
		t.Errorf("vex list = %q, %v; want the name and source", out, err)
	}

	bad := filepath.Join(t.TempDir(), "spdx.json")
	if err := os.WriteFile(bad, []byte(`{"spdxVersion":"SPDX-2.3"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, args := range [][]string{
		{"add", "other", bad}, // not VEX
		{"add", "other", filepath.Join(t.TempDir(), "missing")}, // no such file
		{"add", "has space", vex},                               // bad name
		{"remove", "missing"},                                   // no such name
	} {
		if _, err := runRootCmd(t, baseDir, append([]string{"security", "vex"}, args...)...); err == nil {
			t.Errorf("vex %v: error = nil, want one", args)
		}
	}
}

// TestSecurityScanFailOnUnscanned scans a package with a component the
// fake scanner doesn't support (npm): it's skipped either way, but only
// fails the scan when asked to.
func TestSecurityScanFailOnUnscanned(t *testing.T) {
	baseDir, component := setUpGatedPackage(t)
	unsupported := cdx.Component{Name: "b", Version: "1.0", PackageURL: "pkg:npm/b@1.0"}
	writePackage(t, baseDir, gatedTag, component, unsupported)

	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag); err != nil {
		t.Fatalf("no gate: %v, want none", err)
	}

	unscannedOnly := func(err error) bool {
		var gateErr *security.GateError
		return errors.As(err, &gateErr) && len(gateErr.Findings) == 0 &&
			len(gateErr.Unscanned) == 1 && gateErr.Unscanned[0].Component.PackageURL == unsupported.PackageURL
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "unscanned"); !unscannedOnly(err) {
		t.Errorf("--fail-on unscanned: %v, want a gate failure on just %s", err, unsupported.PackageURL)
	}
	// The scanned component's report is written even when the gate fails.
	readReport(t, baseDir, component)

	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-gate", "--fail-on", "unscanned"); err == nil || errors.As(err, new(*security.GateError)) {
		t.Errorf("--skip-gate --fail-on unscanned: %v, want a flag error", err)
	}

	// A rule asking for it applies too, and --skip-gate drops it.
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--match", "registry.example.com/team", "--fail-on", "unscanned"); err != nil {
		t.Fatalf("policy create: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag); !unscannedOnly(err) {
		t.Errorf("with a rule: %v, want a gate failure on just %s", err, unsupported.PackageURL)
	}
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-gate"); err != nil {
		t.Errorf("--skip-gate over the rule: %v, want none", err)
	}
	// --fail-on replaces all of the rule's conditions, unscanned included.
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "critical"); err != nil {
		t.Errorf("--fail-on critical over the rule: %v, want none", err)
	}
	// Both conditions at once fail on both.
	var gateErr *security.GateError
	_, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "high,unscanned")
	if !errors.As(err, &gateErr) || len(gateErr.Findings) != 1 || len(gateErr.Unscanned) != 1 {
		t.Errorf("--fail-on high,unscanned: %v, want one finding and one unscanned component", err)
	}
	if out, err := runRootCmd(t, baseDir, "security", "policy", "list"); err != nil || !strings.Contains(out, " unscanned ") {
		t.Errorf("policy list = %q, %v; want the rule's FAIL-ON to list unscanned", out, err)
	}
}

func TestCheckGateListsSkipped(t *testing.T) {
	skipped := []security.Skipped{
		{Component: cdx.Component{PackageURL: "pkg:npm/b@1.0"}, Reason: `unsupported type "npm"`},
		{Component: cdx.Component{Name: "c", Version: "2.0"}, Reason: "no detectable type: no package URL"},
	}
	var out bytes.Buffer
	result := security.ScanResult{Scanners: []string{"grype", "trivy"}, Components: 5, Skipped: skipped}
	if err := checkGate(&out, slog.New(slog.DiscardHandler), security.Gate{}, result); err != nil {
		t.Fatalf("checkGate: %v", err)
	}
	for _, want := range []string{"2 of 5 components not scanned by grype or trivy", "pkg:npm/b@1.0", `unsupported type "npm"`, "c@2.0", "no detectable type"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	result.Skipped = nil
	if err := checkGate(&out, slog.New(slog.DiscardHandler), security.Gate{}, result); err != nil || out.Len() != 0 {
		t.Errorf("nothing skipped: %v, %q; want no error and no output", err, out.String())
	}
}

func TestFailsOn(t *testing.T) {
	for _, tc := range []struct {
		rule security.Rule
		want string
	}{
		{security.Rule{}, ""},
		{security.Rule{FailOn: "high"}, "high"},
		{security.Rule{FailOnUnscanned: true}, "unscanned"},
		{security.Rule{FailOn: "high", FailOnUnscanned: true}, "high,unscanned"},
	} {
		if got := failsOn(tc.rule); got != tc.want {
			t.Errorf("failsOn(%+v) = %q, want %q", tc.rule, got, tc.want)
		}
	}
}

// TestSecurityScanSeveralScanners scans a package two scanners each
// cover part of: grype the image, binscan the binary, and neither the
// npm package. Both gate it together, and only what neither scanned
// counts as unscanned.
func TestSecurityScanSeveralScanners(t *testing.T) {
	baseDir := t.TempDir()
	usePlugin(t, baseDir, "grype")
	usePlugin(t, baseDir, "binscan")
	t.Setenv("FAKESECURITY_SUPPORTED_COMPONENTS_GRYPE", `{"types":{"oci":"purl"},"scans":["sca"]}`)
	t.Setenv("FAKESECURITY_SUPPORTED_COMPONENTS_BINSCAN", `{"types":{"generic":"purl"},"scans":["binary"]}`)

	image := cdx.Component{Name: "app", Version: "1.0", PackageURL: "pkg:oci/app@1.0"}
	binary := cdx.Component{Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0"}
	npm := cdx.Component{Name: "b", Version: "1.0", PackageURL: "pkg:npm/b@1.0"}
	writeResponsesFile(t, map[string]string{
		image.PackageURL:  `{"vulnerabilities":[{"id":"CVE-IMAGE","ratings":[{"severity":"high"}],"affects":[{"ref":"pkg:oci/app@1.0"}]}]}`,
		binary.PackageURL: `{"vulnerabilities":[{"id":"CVE-BINARY","ratings":[{"severity":"critical"}],"affects":[{"ref":"pkg:generic/tool@1.0"}]}]}`,
	})
	// Listed twice each: a repeat is still one component, scanned or not.
	writePackage(t, baseDir, gatedTag, image, binary, npm, binary, npm)

	var gateErr *security.GateError
	_, err := runRootCmd(t, baseDir, "security", "scan", "grype,binscan", gatedTag, "--fail-on", "high,unscanned")
	if !errors.As(err, &gateErr) {
		t.Fatalf("both scanners: %v, want a gate failure", err)
	}
	var ids []string
	for _, f := range gateErr.Findings {
		ids = append(ids, f.ID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"CVE-BINARY", "CVE-IMAGE"}) {
		t.Errorf("findings = %v, want one from each scanner", ids)
	}
	if len(gateErr.Unscanned) != 1 || gateErr.Unscanned[0].Component.PackageURL != npm.PackageURL {
		t.Errorf("unscanned = %+v, want just %s", gateErr.Unscanned, npm.PackageURL)
	}

	// Each component has a report from the scanner that supports it.
	for c, scanner := range map[cdx.Component]string{image: "grype", binary: "binscan"} {
		if stored, err := security.ReadReports(baseDir, layout.PurlHash(c.PackageURL)); err != nil || len(stored) != 1 || stored[0].Scanner != scanner {
			t.Errorf("%s's reports = %+v, %v; want one by %s", c.PackageURL, stored, err, scanner)
		}
	}

	// grype alone leaves the binary unscanned too.
	_, err = runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "unscanned")
	if !errors.As(err, &gateErr) || len(gateErr.Unscanned) != 2 {
		t.Errorf("grype alone: %v, want two unscanned components", err)
	}

	for _, scanners := range []string{"grype,grype", "grype,", "grype,missing"} {
		if _, err := runRootCmd(t, baseDir, "security", "scan", scanners, gatedTag); err == nil || errors.As(err, new(*security.GateError)) {
			t.Errorf("scanners %q: %v, want an error naming them", scanners, err)
		}
	}

	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype,binscan", "--match", "registry.example.com/team"); err != nil {
		t.Fatalf("policy create: %v", err)
	}
	if out, err := runRootCmd(t, baseDir, "security", "policy", "list"); err != nil || !strings.Contains(out, "grype,binscan") {
		t.Errorf("policy list = %q, %v; want the rule's scanners listed", out, err)
	}
}

// TestSecurityScanPassesInput scans a package with a scanner that
// supports images by purl and generic files only from their pulled
// files: only the file gets --input, its pulled layer.
func TestSecurityScanPassesInput(t *testing.T) {
	baseDir := t.TempDir()
	usePlugin(t, baseDir, "binscan")
	t.Setenv("FAKESECURITY_SUPPORTED_COMPONENTS_BINSCAN", `{"types":{"oci":"purl","generic":"files"},"scans":["binary"]}`)
	inputs := filepath.Join(t.TempDir(), "inputs")
	t.Setenv("FAKESECURITY_INPUT_LOG", inputs)

	image := cdx.Component{Name: "app", Version: "1.0", PackageURL: "pkg:oci/app@1.0"}
	file := cdx.Component{Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0"}
	writePackage(t, baseDir, gatedTag, image, file)

	// The file isn't pulled yet: there's nothing to pass, so it's skipped.
	var gateErr *security.GateError
	_, err := runRootCmd(t, baseDir, "security", "scan", "binscan", gatedTag, "--fail-on", "unscanned")
	if !errors.As(err, &gateErr) || len(gateErr.Unscanned) != 1 || !strings.Contains(gateErr.Unscanned[0].Reason, "pulled files") {
		t.Fatalf("file not pulled: %v, want it unscanned for want of its files", err)
	}

	layer := layout.ComponentLayer(baseDir, file.PackageURL)
	if err := os.MkdirAll(layer, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layer, "tool"), []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(inputs)
	if _, err := runRootCmd(t, baseDir, "security", "scan", "binscan", gatedTag, "--fail-on", "unscanned"); err != nil {
		t.Fatalf("file pulled: %v, want both scanned", err)
	}
	log, _ := os.ReadFile(inputs)
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		purl, input, _ := strings.Cut(line, "\t")
		got[purl] = input
	}
	if got[image.PackageURL] != "" || got[file.PackageURL] != layer {
		t.Errorf("--input given = %v, want none for the image and %s for the file", got, layer)
	}
	if stored, err := security.ReadReports(baseDir, layout.PurlHash(file.PackageURL)); err != nil || len(stored) != 1 {
		t.Errorf("file's reports = %+v, %v; want binscan's", stored, err)
	}
}

// TestSecurityScanUnanalyzable scans a component the scanner reports it
// couldn't analyze: it counts as unscanned, with no report.
func TestSecurityScanUnanalyzable(t *testing.T) {
	baseDir := t.TempDir()
	usePlugin(t, baseDir, "grype")
	component := cdx.Component{Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}
	writeResponsesFile(t, map[string]string{component.PackageURL: `{"vulnerabilities":[],"unscanned":"no packages found"}`})
	writePackage(t, baseDir, gatedTag, component)

	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag); err != nil {
		t.Fatalf("no gate: %v, want none", err)
	}
	var gateErr *security.GateError
	_, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--fail-on", "unscanned")
	if !errors.As(err, &gateErr) || len(gateErr.Unscanned) != 1 || gateErr.Unscanned[0].Reason != "grype couldn't analyze it: no packages found" {
		t.Errorf("--fail-on unscanned: %v, want it unscanned with grype's reason", err)
	}
	if stored, err := security.ReadReports(baseDir, layout.PurlHash(component.PackageURL)); err != nil || len(stored) != 0 {
		t.Errorf("reports = %+v, %v; want none for a component nothing analyzed", stored, err)
	}
}
