package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/security"
)

// hookComponent is the one component of every hook test package: one
// high and one low vulnerability, per setUpHookPackage's responses.
var hookComponent = cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0"}

const hookTag = "registry.example.com/team/app:1.0"

// setUpHookPackage records hookTag in a fresh data directory — its SBOM
// and a pulled layer, everything save needs to produce a tarball for
// the load tests — with the fake scanner installed as "grype".
func setUpHookPackage(t *testing.T) string {
	t.Helper()
	baseDir := t.TempDir()
	usePlugin(t, baseDir, "grype")
	writeHookResponses(t)
	writePackage(t, baseDir, hookTag, hookComponent)

	layerDir := filepath.Join(baseDir, "layers", plugin.PurlHash(hookComponent))
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatalf("mkdir layer: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "artifact"), []byte("contents"), 0o644); err != nil {
		t.Fatalf("write layer: %v", err)
	}
	return baseDir
}

func writeHookResponses(t *testing.T) {
	t.Helper()
	writeResponsesFile(t, map[string]string{
		"pkg:generic/a@1.0": `{"vulnerabilities":[
			{"id":"CVE-HIGH","ratings":[{"severity":"high"}],"affects":[{"ref":"pkg:generic/a@1.0"}]},
			{"id":"CVE-LOW","ratings":[{"severity":"low"}],"affects":[{"ref":"pkg:generic/a@1.0"}]}
		]}`,
	})
}

// saveHookPackage saves hookTag, unscanned, to a tarball.
func saveHookPackage(t *testing.T) string {
	t.Helper()
	baseDir := setUpHookPackage(t)
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", hookTag, "--output", archive); err != nil {
		t.Fatalf("save: %v", err)
	}
	return archive
}

func isGateError(err error) bool {
	var gateErr *security.GateError
	return errors.As(err, &gateErr)
}

func TestLoadScanGate(t *testing.T) {
	archive := saveHookPackage(t)

	destDir := t.TempDir()
	usePlugin(t, destDir, "grype")

	// A failing gate writes nothing — no SBOM, no tag.
	_, err := runRootCmd(t, destDir, "load", "--input", archive, "--scan", "grype", "--fail-on", "high")
	if !isGateError(err) {
		t.Fatalf("load --fail-on high: error = %v, want a gate failure", err)
	}
	if repos, _ := build.ReadRepositories(destDir); len(repos) != 0 {
		t.Errorf("tags recorded despite a failing gate: %v", repos)
	}
	if _, err := os.Stat(filepath.Join(destDir, "manifests")); !os.IsNotExist(err) {
		t.Errorf("manifests written despite a failing gate: err = %v", err)
	}

	// A passing gate loads it, keeping the fresh report.
	if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--scan", "grype", "--fail-on", "critical"); err != nil {
		t.Fatalf("load --fail-on critical: %v", err)
	}
	if _, err := build.ResolveTag(destDir, hookTag); err != nil {
		t.Errorf("tag not recorded after a passing gate: %v", err)
	}
	readReport(t, destDir, hookComponent)

	// Gating a load needs a fresh scan: the package's own reports are
	// never taken as a verdict.
	if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--fail-on", "high"); err == nil || isGateError(err) {
		t.Errorf("load --fail-on without --scan: error = %v, want a request for --scan", err)
	}
	if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--skip-scan", "--scan", "grype"); err == nil {
		t.Error("load --skip-scan --scan: error = nil, want a flag error")
	}

	// A scan on pull is only ever a gate: --scan with nothing to refuse
	// on is an error, not a scan that can't stop anything.
	emptyDir := t.TempDir()
	usePlugin(t, emptyDir, "grype")
	if _, err := runRootCmd(t, emptyDir, "load", "--input", archive, "--scan", "grype"); err == nil || isGateError(err) {
		t.Errorf("load --scan without a threshold: error = %v, want a request for --fail-on", err)
	}
	if repos, _ := build.ReadRepositories(emptyDir); len(repos) != 0 {
		t.Errorf("tags recorded despite the refused scan: %v", repos)
	}

	// One-off exemptions belong to "bomify security scan"; pull and load
	// rely on a rule's stored VEX.
	for _, flag := range []string{"--ignore", "--vex"} {
		if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--scan", "grype", "--fail-on", "high", flag, "x"); err == nil {
			t.Errorf("load %s: error = nil, want an unknown-flag error", flag)
		}
	}
}

func TestPolicyRuleOnHooks(t *testing.T) {
	archive := saveHookPackage(t)
	destDir := t.TempDir()
	usePlugin(t, destDir, "grype")

	// A rule without --on doesn't scan at hooks.
	if _, err := runRootCmd(t, destDir, "security", "policy", "create", "grype", "--fail-on", "high"); err != nil {
		t.Fatalf("policy create: %v", err)
	}
	if _, err := runRootCmd(t, destDir, "load", "--input", archive); err != nil {
		t.Fatalf("load with a rule not on pull: %v", err)
	}

	// With --on pull, the same rule scans and gates every load.
	if _, err := runRootCmd(t, destDir, "security", "policy", "create", "grype", "--fail-on", "high", "--on", "pull"); err != nil {
		t.Fatalf("policy create --on pull: %v", err)
	}
	if _, err := runRootCmd(t, destDir, "load", "--input", archive); !isGateError(err) {
		t.Errorf("load with a rule on pull: error = %v, want a gate failure", err)
	}
	if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--skip-scan"); err != nil {
		t.Errorf("load --skip-scan over a rule on pull: %v", err)
	}
	if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--fail-on", "critical"); err != nil {
		t.Errorf("load --fail-on critical over a rule on pull: %v", err)
	}

	if _, err := runRootCmd(t, destDir, "security", "policy", "create", "grype", "--match", "x", "--on", "pull"); err == nil {
		t.Error("policy create --on pull without --fail-on: error = nil, want one")
	}
	for _, hook := range []string{"deploy", "build", "push"} {
		if _, err := runRootCmd(t, destDir, "security", "policy", "create", "grype", "--on", hook); err == nil {
			t.Errorf("policy create --on %s: error = nil, want an unknown-hook error", hook)
		}
	}
}
