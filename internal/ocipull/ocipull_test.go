package ocipull

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"bomify/internal/build"
	"bomify/internal/ocitransfer"
)

// pushFixture builds a local OCI-layout store containing one artifact
// manifest: config is sbomBytes, layers are the given (purl, content)
// pairs. It returns the store (itself an oras.ReadOnlyTarget, so Pull can
// consume it directly, exercising the real oras-go resolve/fetch paths with
// no network involved) and the tag the manifest was pushed under.
func pushFixture(t *testing.T, sbomBytes []byte, layerContents map[string][]byte) (*oci.Store, string) {
	t.Helper()

	ctx := context.Background()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	configDesc := ocispec.Descriptor{
		MediaType: "application/vnd.cyclonedx+json",
		Digest:    digestOf(sbomBytes),
		Size:      int64(len(sbomBytes)),
	}
	if err := store.Push(ctx, configDesc, bytesReader(sbomBytes)); err != nil {
		t.Fatalf("push config: %v", err)
	}

	var layerDescs []ocispec.Descriptor
	for purl, data := range layerContents {
		desc := ocispec.Descriptor{
			MediaType: "application/octet-stream",
			Digest:    digestOf(data),
			Size:      int64(len(data)),
			Annotations: map[string]string{
				// The purl itself is not a safe filename (it contains "/"
				// and ":"), so this also exercises layerFilename's fallback
				// to the digest for an unsafe title.
				ocispec.AnnotationTitle: purl,
				AnnotationPurl:          purl,
			},
		}
		if err := store.Push(ctx, desc, bytesReader(data)); err != nil {
			t.Fatalf("push layer %s: %v", purl, err)
		}
		layerDescs = append(layerDescs, desc)
	}

	manifestDesc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "application/vnd.bomify.package.v1+json", oras.PackManifestOptions{
		ConfigDescriptor: &configDesc,
		Layers:           layerDescs,
	})
	if err != nil {
		t.Fatalf("pack manifest: %v", err)
	}

	const tag = "test"
	if err := store.Tag(ctx, manifestDesc, tag); err != nil {
		t.Fatalf("tag manifest: %v", err)
	}

	return store, tag
}

func digestOf(data []byte) digest.Digest {
	sum := sha256.Sum256(data)
	return digest.Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func bytesReader(data []byte) io.Reader { return &staticReader{data: data} }

type staticReader struct {
	data []byte
	pos  int
}

func (r *staticReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func TestPullRestoresConfigAndLayers(t *testing.T) {
	sbomBytes := []byte(`{"bomFormat":"CycloneDX","components":[]}`)
	layers := map[string][]byte{
		"pkg:generic/foo@1.0?download_url=https://example.com/foo": []byte("foo contents"),
		"pkg:generic/bar@2.0?download_url=https://example.com/bar": []byte("bar contents, a bit longer than foo's"),
	}

	store, tag := pushFixture(t, sbomBytes, layers)

	dataDir := t.TempDir()

	var progressCalls int32
	progress := func(name string, size int64) io.WriteCloser {
		atomic.AddInt32(&progressCalls, 1)
		return ocitransfer.Discard(name, size)
	}

	result, err := Pull(context.Background(), store, tag, dataDir, 2, progress)
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	wantSBOMHash := digestOf(sbomBytes).Encoded()
	if result.SBOMHash != wantSBOMHash {
		t.Errorf("SBOMHash = %s, want %s", result.SBOMHash, wantSBOMHash)
	}

	manifestPath := build.ManifestPath(dataDir, result.SBOMHash)
	got, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if string(got) != string(sbomBytes) {
		t.Errorf("manifest content = %q, want %q", got, sbomBytes)
	}

	if len(result.Layers) != len(layers) {
		t.Fatalf("got %d layers, want %d", len(result.Layers), len(layers))
	}

	for _, layer := range result.Layers {
		wantContent, ok := layers[layer.Purl]
		if !ok {
			t.Errorf("unexpected layer purl %q", layer.Purl)
			continue
		}

		wantHash := digestOf(wantContent).Encoded()
		if layer.Hash != wantHash {
			t.Errorf("layer %s hash = %s, want %s", layer.Purl, layer.Hash, wantHash)
		}

		gotContent, err := os.ReadFile(layer.Path)
		if err != nil {
			t.Fatalf("read layer file %s: %v", layer.Path, err)
		}
		if string(gotContent) != string(wantContent) {
			t.Errorf("layer %s content = %q, want %q", layer.Purl, gotContent, wantContent)
		}

		wantDir := filepath.Join(dataDir, "layers", wantHash)
		if filepath.Dir(layer.Path) != wantDir {
			t.Errorf("layer %s path dir = %s, want %s", layer.Purl, filepath.Dir(layer.Path), wantDir)
		}
	}

	// One progress call for the config, one per layer.
	if got := atomic.LoadInt32(&progressCalls); got != int32(1+len(layers)) {
		t.Errorf("progress called %d times, want %d", got, 1+len(layers))
	}
}

func TestPullRejectsNonSHA256Digest(t *testing.T) {
	// A manifest whose config uses a non-sha256 digest algorithm should be
	// rejected outright: bomify's on-disk layout is keyed by sha256 hex
	// everywhere else (internal/plugin, internal/build), so silently
	// accepting another algorithm here would produce files nothing else
	// could find.
	sbomBytes := []byte(`{}`)
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	ctx := context.Background()
	configDesc := ocispec.Descriptor{
		MediaType: "application/vnd.cyclonedx+json",
		Digest:    digest.Digest("sha512:" + hex.EncodeToString(make([]byte, 64))),
		Size:      int64(len(sbomBytes)),
	}

	manifestDesc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "application/vnd.bomify.package.v1+json", oras.PackManifestOptions{
		ConfigDescriptor: &configDesc,
	})
	if err != nil {
		t.Fatalf("pack manifest: %v", err)
	}
	if err := store.Tag(ctx, manifestDesc, "test"); err != nil {
		t.Fatalf("tag manifest: %v", err)
	}

	_, err = Pull(ctx, store, "test", t.TempDir(), 1, nil)
	if err == nil {
		t.Fatal("Pull() error = nil, want error for non-sha256 digest")
	}
}

func TestLayerFilename(t *testing.T) {
	digestFallback := digest.Digest("sha256:" + hex.EncodeToString(make([]byte, 32)))

	tests := []struct {
		name  string
		title string
		want  string
	}{
		{"safe title used as-is", "chart.tgz", "chart.tgz"},
		{"no title falls back to digest", "", digestFallback.Encoded()},
		{"path separator falls back to digest", "../../etc/passwd", digestFallback.Encoded()},
		{"backslash falls back to digest", `..\..\windows\system32`, digestFallback.Encoded()},
		{"purl-shaped title falls back to digest", "pkg:generic/foo@1.0?x=y", digestFallback.Encoded()},
		{"bare traversal falls back to digest", "..", digestFallback.Encoded()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := ocispec.Descriptor{
				Digest:      digestFallback,
				Annotations: map[string]string{ocispec.AnnotationTitle: tt.title},
			}
			if got := layerFilename(desc); got != tt.want {
				t.Errorf("layerFilename(title=%q) = %q, want %q", tt.title, got, tt.want)
			}
		})
	}
}
