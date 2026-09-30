package save

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
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

func writeComponentFixture(t *testing.T, baseDir string, component cdx.Component, files map[string]string) {
	t.Helper()

	hash := layout.PurlHash(component.PackageURL)

	manifestPath := layout.Manifest(baseDir, hash)
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(manifestPath), err)
	}
	if err := os.WriteFile(manifestPath, []byte(`{"component":{}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", manifestPath, err)
	}

	layerDir := layout.Layer(baseDir, hash)
	for name, content := range files {
		path := filepath.Join(layerDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()

	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	return files
}

// TestSaveThenLoadRoundTrip exercises Save and Load against real,
// separate data directories — as if on two different machines — with two
// tags sharing one component, proving: (1) the tarball is fully
// self-contained (Load needs nothing from the original baseDir), (2) a
// shared component is stored once but restored correctly under both
// tags, and (3) both tags land in the new baseDir's repositories.json
// pointing at the same package.
func TestSaveThenLoadRoundTrip(t *testing.T) {
	componentA := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	componentB := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "b", Version: "1.0", PackageURL: "pkg:generic/b@1.0?download_url=https://example.com/b"}

	sourceDir := t.TempDir()
	writeComponentFixture(t, sourceDir, componentA, map[string]string{"artifact": "single file contents"})
	writeComponentFixture(t, sourceDir, componentB, map[string]string{
		"oci-layout":        `{"imageLayoutVersion":"1.0.0"}`,
		"blobs/sha256/abcd": "fake blob content",
	})

	sbom1Path := filepath.Join(t.TempDir(), "sbom1.cdx.json")
	writeSBOM(t, sbom1Path, componentA, componentB)
	sbom1Hash, _, err := build.RecordManifest(sourceDir, sbom1Path)
	if err != nil {
		t.Fatalf("RecordManifest (sbom1): %v", err)
	}
	if err := build.UpdateRepositories(sourceDir, []string{"appA:v1.0"}, sbom1Hash); err != nil {
		t.Fatalf("UpdateRepositories (appA): %v", err)
	}

	sbom2Path := filepath.Join(t.TempDir(), "sbom2.cdx.json")
	writeSBOM(t, sbom2Path, componentA) // shares componentA with sbom1
	sbom2Hash, _, err := build.RecordManifest(sourceDir, sbom2Path)
	if err != nil {
		t.Fatalf("RecordManifest (sbom2): %v", err)
	}
	if err := build.UpdateRepositories(sourceDir, []string{"appB:v1.0"}, sbom2Hash); err != nil {
		t.Fatalf("UpdateRepositories (appB): %v", err)
	}

	ctx := context.Background()

	var archive bytes.Buffer
	if err := Save(ctx, sourceDir, []string{"appA:v1.0", "appB:v1.0"}, &archive, transfer.Options{Concurrency: 2}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load into a completely fresh directory: nothing from sourceDir
	// should be needed or referenced.
	destDir := t.TempDir()
	restored, err := Load(ctx, destDir, bytes.NewReader(archive.Bytes()), transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	gotTags := map[string]bool{}
	for _, l := range restored {
		gotTags[l.Tag] = true
		if !strings.HasPrefix(l.ManifestDigest, "sha256:") {
			t.Errorf("Load() restored %s with digest %q, want sha256:...", l.Tag, l.ManifestDigest)
		}
	}
	if !gotTags["appA:v1.0"] || !gotTags["appB:v1.0"] {
		t.Errorf("Load() restored %v, want both appA:v1.0 and appB:v1.0", restored)
	}

	repos, err := build.ReadRepositories(destDir)
	if err != nil {
		t.Fatalf("ReadRepositories: %v", err)
	}
	if repos["appA"]["v1.0"] == "" || repos["appB"]["v1.0"] == "" {
		t.Errorf("repositories.json = %+v, want both appA:v1.0 and appB:v1.0 mapped", repos)
	}

	// Both manifests should exist, byte-identical to their originals.
	for _, tc := range []struct {
		path, sbomPath string
	}{
		{layout.Manifest(destDir, repos["appA"]["v1.0"]), sbom1Path},
		{layout.Manifest(destDir, repos["appB"]["v1.0"]), sbom2Path},
	} {
		got, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read restored manifest %s: %v", tc.path, err)
		}
		want, err := os.ReadFile(tc.sbomPath)
		if err != nil {
			t.Fatalf("read original sbom %s: %v", tc.sbomPath, err)
		}
		if string(got) != string(want) {
			t.Errorf("restored manifest %s = %q, want %q", tc.path, got, want)
		}
	}

	// componentA (shared) and componentB should both be restored intact.
	aDir := layout.ComponentLayer(destDir, componentA.PackageURL)
	if files := readDir(t, aDir); files["artifact"] != "single file contents" {
		t.Errorf("componentA restored content = %v", files)
	}

	bDir := layout.ComponentLayer(destDir, componentB.PackageURL)
	files := readDir(t, bDir)
	if files["oci-layout"] != `{"imageLayoutVersion":"1.0.0"}` || files["blobs/sha256/abcd"] != "fake blob content" {
		t.Errorf("componentB restored content = %v", files)
	}
}

// TestSaveThenLoadCarriesVulnerabilityReportOnMatch covers the "if there
// is a match" half of save/load carrying vulnerability reports along
// with a package: componentA has a local vulnerability report (as
// `bomify security scan` would have written); componentB has none. Only
// componentA's report should reappear in the loaded directory.
func TestSaveThenLoadCarriesVulnerabilityReportOnMatch(t *testing.T) {
	componentA := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "a", Version: "1.0", PackageURL: "pkg:generic/a@1.0?download_url=https://example.com/a"}
	componentB := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "b", Version: "1.0", PackageURL: "pkg:generic/b@1.0?download_url=https://example.com/b"}

	sourceDir := t.TempDir()
	writeComponentFixture(t, sourceDir, componentA, map[string]string{"artifact": "single file contents"})
	writeComponentFixture(t, sourceDir, componentB, map[string]string{"artifact": "other contents"})

	reportBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"vulnerabilities":[{"id":"CVE-TEST"}]}`)
	reportPath := layout.ComponentReport(sourceDir, componentA.PackageURL)
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		t.Fatalf("mkdir vulnerabilities dir: %v", err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0o644); err != nil {
		t.Fatalf("write vulnerability report: %v", err)
	}

	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	writeSBOM(t, sbomPath, componentA, componentB)
	sbomHash, _, err := build.RecordManifest(sourceDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	if err := build.UpdateRepositories(sourceDir, []string{"myapp:v1.0"}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	ctx := context.Background()

	var archive bytes.Buffer
	if err := Save(ctx, sourceDir, []string{"myapp:v1.0"}, &archive, transfer.Options{Concurrency: 2}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	destDir := t.TempDir()
	if _, err := Load(ctx, destDir, bytes.NewReader(archive.Bytes()), transfer.Options{Concurrency: 2}); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	got, err := os.ReadFile(layout.ComponentReport(destDir, componentA.PackageURL))
	if err != nil {
		t.Fatalf("read restored vulnerability report: %v", err)
	}
	if string(got) != string(reportBytes) {
		t.Errorf("restored vulnerability report = %q, want %q", got, reportBytes)
	}

	if _, err := os.Stat(layout.ComponentReport(destDir, componentB.PackageURL)); !os.IsNotExist(err) {
		t.Errorf("componentB got a vulnerability report, want none: err = %v", err)
	}
}

func TestSaveFailsForUnknownTag(t *testing.T) {
	baseDir := t.TempDir()

	var archive bytes.Buffer
	if err := Save(context.Background(), baseDir, []string{"nope:v1.0"}, &archive, transfer.Options{Concurrency: 1}); err == nil {
		t.Fatal("Save() error = nil, want error for a tag that doesn't resolve to anything")
	}
}

func TestLoadFailsForNonArchiveInput(t *testing.T) {
	baseDir := t.TempDir()

	_, err := Load(context.Background(), baseDir, bytes.NewReader([]byte("not a tar file")), transfer.Options{Concurrency: 1})
	if err == nil {
		t.Fatal("Load() error = nil, want error for non-tar input")
	}
}
