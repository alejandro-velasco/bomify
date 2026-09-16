package push

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

var (
	singleFileComponent = cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "single-file",
		Version:    "1.0",
		PackageURL: "pkg:generic/single-file@1.0?download_url=https://example.com/single-file",
	}
	multiFileComponent = cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "multi-file",
		Version:    "2.0",
		PackageURL: "pkg:oci/multi-file@2.0?repository_url=example.com/multi-file",
	}
)

// TestPushThenPullRoundTrip exercises Push against a real local OCI store
// (no mocking of oras-go), then pulls the result back with the real
// pull.Pull — proving the two independently-written packages agree on
// the artifact format end to end, not just that Push runs without error.
// One component's layer is a single file (as bomify-plugin-generic
// produces); the other's is a directory tree (as bomify-plugin-oci
// produces), exercising Push's tar-the-whole-directory path.
func TestPushThenPullRoundTrip(t *testing.T) {
	baseDir := t.TempDir()

	writeLayer(t, baseDir, singleFileComponent, map[string]string{
		"artifact": "single file contents",
	})
	writeLayer(t, baseDir, multiFileComponent, map[string]string{
		"oci-layout":        `{"imageLayoutVersion":"1.0.0"}`,
		"blobs/sha256/abcd": "fake blob content",
	})

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"single-file","version":"1.0","purl":"pkg:generic/single-file@1.0?download_url=https://example.com/single-file"},` +
		`{"type":"container","name":"multi-file","version":"2.0","purl":"pkg:oci/multi-file@2.0?repository_url=example.com/multi-file"}` +
		`]}`)
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}

	sbomHash, _, err := build.RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	ctx := context.Background()
	const tag = "test"

	result, err := Push(ctx, store, tag, baseDir, sbomHash, 2, nil)
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if result.ManifestDigest == "" {
		t.Error("ManifestDigest is empty")
	}
	if len(result.Layers) != 2 {
		t.Fatalf("got %d layers, want 2", len(result.Layers))
	}

	pulledDir := t.TempDir()
	pullResult, err := pull.Pull(ctx, store, tag, pulledDir, 2, nil)
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	gotManifest, err := os.ReadFile(build.ManifestPath(pulledDir, pullResult.SBOMHash))
	if err != nil {
		t.Fatalf("read pulled manifest: %v", err)
	}
	if string(gotManifest) != string(sbomBytes) {
		t.Errorf("pulled manifest = %q, want %q", gotManifest, sbomBytes)
	}

	if len(pullResult.Layers) != 2 {
		t.Fatalf("pulled %d layers, want 2", len(pullResult.Layers))
	}

	for _, layer := range pullResult.Layers {
		var component cdx.Component
		switch layer.Purl {
		case singleFileComponent.PackageURL:
			component = singleFileComponent
		case multiFileComponent.PackageURL:
			component = multiFileComponent
		default:
			t.Errorf("unexpected layer purl %q", layer.Purl)
			continue
		}

		// The whole point of unpacking on pull: the layer must land at
		// exactly the path `bomify build` would have used for this
		// component, not some digest-keyed directory of Pull's own
		// invention.
		wantPath := filepath.Join(pulledDir, "layers", plugin.PurlHash(component))
		if layer.Path != wantPath {
			t.Errorf("layer %s path = %s, want %s", layer.Purl, layer.Path, wantPath)
		}

		files := readDir(t, layer.Path)
		switch layer.Purl {
		case singleFileComponent.PackageURL:
			if files["artifact"] != "single file contents" {
				t.Errorf("single-file layer content = %v", files)
			}
		case multiFileComponent.PackageURL:
			if files["oci-layout"] != `{"imageLayoutVersion":"1.0.0"}` || files["blobs/sha256/abcd"] != "fake blob content" {
				t.Errorf("multi-file layer content = %v", files)
			}
		}
	}
}

func TestPushFailsWithoutLocalLayer(t *testing.T) {
	baseDir := t.TempDir()

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"missing","version":"1.0","purl":"pkg:generic/missing@1.0?download_url=https://example.com/missing"}` +
		`]}`)
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}

	sbomHash, _, err := build.RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	if _, err := Push(context.Background(), store, "test", baseDir, sbomHash, 1, nil); err == nil {
		t.Fatal("Push() error = nil, want error for a component never built locally")
	}
}

// TestPushSkipsComponentWithoutPurl exercises a component with no package
// URL — which `bomify build` never pulls (see cmd/build.go) — alongside one
// that was pulled normally, proving Push leaves the empty-purl component
// out of the pushed artifact (rather than failing on its missing local
// layer, like TestPushFailsWithoutLocalLayer) and reports it as skipped.
func TestPushSkipsComponentWithoutPurl(t *testing.T) {
	baseDir := t.TempDir()

	writeLayer(t, baseDir, singleFileComponent, map[string]string{
		"artifact": "single file contents",
	})

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"single-file","version":"1.0","purl":"pkg:generic/single-file@1.0?download_url=https://example.com/single-file"},` +
		`{"type":"file","name":"internal-notes","version":"1.0"}` +
		`]}`)
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}

	sbomHash, _, err := build.RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	result, err := Push(context.Background(), store, "test", baseDir, sbomHash, 1, nil)
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	if len(result.Layers) != 1 || result.Layers[0].Purl != singleFileComponent.PackageURL {
		t.Errorf("Layers = %+v, want exactly the single-file component", result.Layers)
	}

	if len(result.Skipped) != 1 || result.Skipped[0] != "internal-notes@1.0" {
		t.Errorf("Skipped = %v, want [\"internal-notes@1.0\"]", result.Skipped)
	}

	pulledDir := t.TempDir()
	if _, err := pull.Pull(context.Background(), store, "test", pulledDir, 1, nil); err != nil {
		t.Fatalf("Pull() error = %v, want the pushed artifact to round-trip despite the skipped component", err)
	}
}

func writeLayer(t *testing.T, baseDir string, component cdx.Component, files map[string]string) {
	t.Helper()

	dir := filepath.Join(baseDir, "layers", plugin.PurlHash(component))
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// readDir reads every regular file under dir into a map keyed by its
// slash-separated path relative to dir.
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
