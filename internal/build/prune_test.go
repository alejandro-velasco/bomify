package build

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/plugin"
)

func writeSBOM(t *testing.T, path string, components ...cdx.Component) {
	t.Helper()

	sbom := struct {
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

	data, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("marshal sbom fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeComponentFixture(t *testing.T, baseDir string, component cdx.Component) {
	t.Helper()

	hash := plugin.PurlHash(component)

	manifestPath := filepath.Join(baseDir, "manifests", hash+".json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(manifestPath), err)
	}
	if err := os.WriteFile(manifestPath, []byte(`{"component":{}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", manifestPath, err)
	}

	layerDir := filepath.Join(baseDir, "layers", hash)
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", layerDir, err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "artifact"), []byte("content"), 0o644); err != nil {
		t.Fatalf("write layer file: %v", err)
	}
}

// writePulledLayerFixture writes only a layer directory for component,
// with no manifest — the layout `bomify pull` produces for a component
// restored from a registry, unlike `bomify build`'s writeComponentFixture
// (which also writes a per-component manifest).
func writePulledLayerFixture(t *testing.T, baseDir string, component cdx.Component) {
	t.Helper()

	layerDir := filepath.Join(baseDir, "layers", plugin.PurlHash(component))
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", layerDir, err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "artifact"), []byte("content"), 0o644); err != nil {
		t.Fatalf("write layer file: %v", err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// deadPID returns a pid guaranteed not to belong to any running process,
// by spawning a throwaway process and waiting for it to exit.
func deadPID(t *testing.T) int {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start throwaway process: %v", err)
	}

	pid := cmd.Process.Pid
	_ = cmd.Wait()

	return pid
}

// TestPruneRemovesOnlyUnreachableManifestsAndLayers is the core
// correctness test: a component shared between a kept (tagged) SBOM and
// an orphaned (untagged) one must survive pruning, while a component
// used only by the orphaned SBOM must not — Prune has to walk reachable
// components from every live tag, not just delete "the orphaned SBOM's
// own stuff" wholesale.
func TestPruneRemovesOnlyUnreachableManifestsAndLayers(t *testing.T) {
	baseDir := t.TempDir()

	componentA := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	componentB := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "b", Version: "1.0", PackageURL: "pkg:generic/b@1.0?download_url=https://example.com/b"}
	componentC := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "c", Version: "1.0", PackageURL: "pkg:generic/c@1.0?download_url=https://example.com/c"}

	writeComponentFixture(t, baseDir, componentA)
	writeComponentFixture(t, baseDir, componentB)
	writeComponentFixture(t, baseDir, componentC)

	keptSBOMPath := filepath.Join(t.TempDir(), "kept.cdx.json")
	writeSBOM(t, keptSBOMPath, componentA, componentB)
	keptHash, _, err := RecordManifest(baseDir, keptSBOMPath)
	if err != nil {
		t.Fatalf("RecordManifest (kept): %v", err)
	}

	orphanSBOMPath := filepath.Join(t.TempDir(), "orphan.cdx.json")
	writeSBOM(t, orphanSBOMPath, componentB, componentC)
	orphanHash, _, err := RecordManifest(baseDir, orphanSBOMPath)
	if err != nil {
		t.Fatalf("RecordManifest (orphan): %v", err)
	}

	if err := UpdateRepositories(baseDir, []string{"myapp:v1.0"}, keptHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	result, err := Prune(baseDir)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	// The orphaned SBOM's own manifest, and component C's manifest and
	// layer (used only by the orphan), should be gone.
	if exists(ManifestPath(baseDir, orphanHash)) {
		t.Error("orphaned SBOM manifest still exists")
	}
	if exists(filepath.Join(baseDir, "manifests", plugin.PurlHash(componentC)+".json")) {
		t.Error("component C's manifest still exists")
	}
	if exists(filepath.Join(baseDir, "layers", plugin.PurlHash(componentC))) {
		t.Error("component C's layer dir still exists")
	}

	// The kept SBOM's own manifest, and components A and B (B being
	// shared with the pruned orphan), must survive.
	if !exists(ManifestPath(baseDir, keptHash)) {
		t.Error("kept SBOM manifest was removed")
	}
	for _, c := range []cdx.Component{componentA, componentB} {
		hash := plugin.PurlHash(c)
		if !exists(filepath.Join(baseDir, "manifests", hash+".json")) {
			t.Errorf("component %s's manifest was removed", c.Name)
		}
		if !exists(filepath.Join(baseDir, "layers", hash)) {
			t.Errorf("component %s's layer dir was removed", c.Name)
		}
	}

	// The orphaned SBOM's own manifest, plus component C's manifest and
	// layer dir (as two separate entries).
	if len(result.Removed) != 3 {
		t.Errorf("Removed = %v, want 3 entries", result.Removed)
	}
}

// TestPruneRemovesUnreachablePulledLayerWithNoManifest guards against the
// real bug this fix addresses: a component restored via `bomify pull`
// (rather than `bomify build`) has a layers/<hash> directory but no
// per-component manifests/<hash>.json — internal/oci/pull never writes
// one, only the SBOM-level manifest. Prune used to discover removal
// candidates solely from manifests/, so such a component's layer
// directory was never even considered for removal and survived forever,
// however unreachable it became.
func TestPruneRemovesUnreachablePulledLayerWithNoManifest(t *testing.T) {
	baseDir := t.TempDir()

	component := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	writePulledLayerFixture(t, baseDir, component)

	// No tags at all, so this component is unreachable.
	result, err := Prune(baseDir)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	hash := plugin.PurlHash(component)
	if exists(filepath.Join(baseDir, "layers", hash)) {
		t.Error("unreachable pulled component's layer dir still exists")
	}
	if len(result.Removed) != 1 || result.Removed[0].Kind != "layer" {
		t.Errorf("Removed = %v, want a single layer entry", result.Removed)
	}
}

func TestPruneSkipsManifestWithLivePidFile(t *testing.T) {
	baseDir := t.TempDir()

	component := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	writeComponentFixture(t, baseDir, component)

	// No tags at all, so this component is unreachable — but a pid file
	// naming a still-running process means a pull is genuinely in
	// flight for it, so Prune should leave it alone rather than deleting
	// out from under that pull. os.Getpid() (this test process) is
	// guaranteed alive for the duration of the test.
	hash := plugin.PurlHash(component)
	pidPath := filepath.Join(baseDir, "manifests", hash+".pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	result, err := Prune(baseDir)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	manifestPath := filepath.Join(baseDir, "manifests", hash+".json")
	if !exists(manifestPath) {
		t.Error("manifest with an in-flight pid file was removed")
	}
	if !exists(filepath.Join(baseDir, "layers", hash)) {
		t.Error("layer dir with an in-flight pid file was removed")
	}
	if !exists(pidPath) {
		t.Error("live pid file was removed")
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != hash {
		t.Errorf("Skipped = %v, want [%s]", result.Skipped, hash)
	}
}

// TestPruneReclaimsManifestWithStalePidFile guards against a related
// bug: a pid file left behind by a pull that crashed (or was Ctrl+C'd)
// without cleaning up used to permanently block that component from
// ever being pruned, since Prune only checked whether the pid file
// existed, not whether its owning process was actually still alive.
func TestPruneReclaimsManifestWithStalePidFile(t *testing.T) {
	baseDir := t.TempDir()

	component := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	writeComponentFixture(t, baseDir, component)

	hash := plugin.PurlHash(component)
	pidPath := filepath.Join(baseDir, "manifests", hash+".pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(deadPID(t))), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	result, err := Prune(baseDir)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	manifestPath := filepath.Join(baseDir, "manifests", hash+".json")
	if exists(manifestPath) {
		t.Error("manifest with a stale pid file was not removed")
	}
	if exists(filepath.Join(baseDir, "layers", hash)) {
		t.Error("layer dir with a stale pid file was not removed")
	}
	if exists(pidPath) {
		t.Error("stale pid file itself was not cleaned up")
	}
	if len(result.Skipped) != 0 {
		t.Errorf("Skipped = %v, want none", result.Skipped)
	}
}

// TestPruneReportsUnprotectedForUnparsableManifest guards against a real
// bug: a tagged SBOM manifest that exists but fails to parse used to be
// treated identically to a missing one, so Prune silently pruned its
// components as unreachable — even though a tag still pointed at it. It
// must instead be reported via PruneResult.Unprotected, loudly, rather
// than the same data loss happening with no signal at all.
func TestPruneReportsUnprotectedForUnparsableManifest(t *testing.T) {
	baseDir := t.TempDir()

	component := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	writeComponentFixture(t, baseDir, component)

	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	writeSBOM(t, sbomPath, component)
	sbomHash, _, err := RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	// Corrupt the recorded manifest after the fact, simulating e.g. a
	// truncated write or on-disk corruption — not something RecordManifest
	// itself would ever produce, but something Prune must still handle
	// safely if it happens.
	if err := os.WriteFile(ManifestPath(baseDir, sbomHash), []byte("not json"), 0o644); err != nil {
		t.Fatalf("corrupt manifest: %v", err)
	}

	if err := UpdateRepositories(baseDir, []string{"myapp:v1.0"}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	result, err := Prune(baseDir)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	if len(result.Unprotected) != 1 || result.Unprotected[0] != sbomHash {
		t.Errorf("Unprotected = %v, want [%s]", result.Unprotected, sbomHash)
	}
}

func TestPruneWithNoManifestsDirectory(t *testing.T) {
	baseDir := t.TempDir()

	result, err := Prune(baseDir)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	if len(result.Removed) != 0 || len(result.Skipped) != 0 {
		t.Errorf("Prune() on an empty baseDir = %+v, want no removed/skipped entries", result)
	}
}
