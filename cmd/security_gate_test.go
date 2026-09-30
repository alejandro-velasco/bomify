package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

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
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-scan"); err != nil {
		t.Errorf("--skip-scan: error = %v, want none", err)
	}
	// --skip-gate, the flag's earlier name, still works as a hidden alias.
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-gate"); err != nil {
		t.Errorf("--skip-gate: error = %v, want none", err)
	}
}

func TestSecurityScanGateFlagValidation(t *testing.T) {
	baseDir, _ := setUpGatedPackage(t)

	for _, args := range [][]string{
		{"--fail-on", "severe"},
		{"--ignore", "CVE-HIGH"},
		{"--skip-scan", "--fail-on", "high"},
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
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-scan", "--vex", vex); err == nil {
		t.Error("--skip-scan --vex: error = nil, want a flag error")
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
