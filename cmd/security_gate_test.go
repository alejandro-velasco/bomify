package cmd

import (
	"errors"
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
	if _, err := runRootCmd(t, baseDir, "security", "scan", "grype", gatedTag, "--skip-gate"); err != nil {
		t.Errorf("--skip-gate: error = %v, want none", err)
	}
}

func TestSecurityScanGateFlagValidation(t *testing.T) {
	baseDir, _ := setUpGatedPackage(t)

	for _, args := range [][]string{
		{"--fail-on", "severe"},
		{"--ignore", "CVE-HIGH"},
		{"--skip-gate", "--fail-on", "high"},
	} {
		if _, err := runRootCmd(t, baseDir, append([]string{"security", "scan", "grype", gatedTag}, args...)...); err == nil || errors.As(err, new(*security.GateError)) {
			t.Errorf("%v: error = %v, want a flag error", args, err)
		}
	}
}

func TestSecurityPolicyCreateListRemove(t *testing.T) {
	baseDir := t.TempDir()

	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--match", "registry.example.com/team", "--fail-on", "high", "--ignore", "CVE-1"); err != nil {
		t.Fatalf("policy create: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype"); err != nil {
		t.Fatalf("policy create (catch-all): %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--fail-on", "severe"); err == nil {
		t.Error("policy create accepted an invalid --fail-on")
	}
	if _, err := runRootCmd(t, baseDir, "security", "policy", "create", "grype", "--ignore", "CVE-1"); err == nil {
		t.Error("policy create accepted --ignore without --fail-on")
	}

	out, err := runRootCmd(t, baseDir, "security", "policy", "list")
	if err != nil {
		t.Fatalf("policy list: %v", err)
	}
	for _, want := range []string{"MATCH", "registry.example.com/team", "high", "CVE-1", "*"} {
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
