package build

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

func TestPruneSkipsManifestWithPidFile(t *testing.T) {
	baseDir := t.TempDir()

	component := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	writeComponentFixture(t, baseDir, component)

	// No tags at all, so this component is unreachable — but a pid file
	// suggests a pull might be in flight for it, so Prune should leave
	// it alone rather than deleting out from under that pull.
	hash := plugin.PurlHash(component)
	pidPath := filepath.Join(baseDir, "manifests", hash+".pid")
	if err := os.WriteFile(pidPath, []byte("12345"), 0o644); err != nil {
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
	if len(result.Skipped) != 1 || result.Skipped[0] != manifestPath {
		t.Errorf("Skipped = %v, want [%s]", result.Skipped, manifestPath)
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
