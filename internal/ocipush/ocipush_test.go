package ocipush

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"oras.land/oras-go/v2/content/oci"

	"bomify/internal/build"
	"bomify/internal/ocipull"
	"bomify/internal/plugin"
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
// ocipull.Pull — proving the two independently-written packages agree on
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
	pullResult, err := ocipull.Pull(ctx, store, tag, pulledDir, 2, nil)
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
		files := untar(t, layer.Path)
		switch layer.Purl {
		case singleFileComponent.PackageURL:
			if files["artifact"] != "single file contents" {
				t.Errorf("single-file layer content = %v", files)
			}
		case multiFileComponent.PackageURL:
			if files["oci-layout"] != `{"imageLayoutVersion":"1.0.0"}` || files["blobs/sha256/abcd"] != "fake blob content" {
				t.Errorf("multi-file layer content = %v", files)
			}
		default:
			t.Errorf("unexpected layer purl %q", layer.Purl)
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

func untar(t *testing.T, path string) map[string]string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	files := map[string]string{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read %s: %v", path, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read content %s: %v", hdr.Name, err)
		}
		files[hdr.Name] = string(data)
	}
	return files
}
