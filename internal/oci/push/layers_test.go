package push

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

var modelComponent = cdx.Component{
	Type:       cdx.ComponentTypeMachineLearningModel,
	Name:       "model",
	Version:    "1.0",
	PackageURL: "pkg:generic/model@1.0?download_url=https://example.com/model",
}

// layerLimits makes transfer.LargeFileSize and transfer.MaxLayerSize
// small for a test.
func layerLimits(t *testing.T, largeFile, maxLayer int64) {
	t.Helper()
	originalLarge, originalMax := transfer.LargeFileSize, transfer.MaxLayerSize
	transfer.LargeFileSize, transfer.MaxLayerSize = largeFile, maxLayer
	t.Cleanup(func() { transfer.LargeFileSize, transfer.MaxLayerSize = originalLarge, originalMax })
}

func newStore(t *testing.T) *oci.Store {
	t.Helper()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	return store
}

func manifestOf(t *testing.T, store *oci.Store, tag string) ocispec.Manifest {
	t.Helper()
	_, data, err := oras.FetchBytes(context.Background(), store, tag, oras.DefaultFetchBytesOptions)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	var manifest ocispec.Manifest
	if err := jsonUnmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestPushSplitsLargeFiles(t *testing.T) {
	layerLimits(t, 16, 40)
	baseDir := t.TempDir()
	files := map[string]string{
		"config.json":     `{"a": 1}`,
		"big.bin":         strings.Repeat("0123456789", 10),
		"nested/huge.bin": strings.Repeat("abcde", 10),
	}
	writeLayer(t, baseDir, modelComponent, files)
	executable := filepath.Join(layout.ComponentLayer(baseDir, modelComponent.PackageURL), "big.bin")
	if err := os.Chmod(executable, 0o755); err != nil {
		t.Fatal(err)
	}
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{modelComponent})
	store := newStore(t)

	if _, err := Push(context.Background(), store, "model", baseDir, sbomHash, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	manifest := manifestOf(t, store, "model")
	var tars, parts []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		switch layer.MediaType {
		case transfer.LayerMediaType:
			tars = append(tars, layer)
		case transfer.FilePartMediaType:
			parts = append(parts, layer)
			if layer.Size > transfer.MaxLayerSize {
				t.Errorf("part of %s is %d bytes, over the %d cap", layer.Annotations[transfer.AnnotationFilePath], layer.Size, transfer.MaxLayerSize)
			}
		}
	}
	// config.json in one tar; big.bin in 40+40+20; nested/huge.bin in 40+10.
	if len(tars) != 1 || len(parts) != 5 {
		t.Fatalf("got %d tar and %d part layers, want 1 and 5", len(tars), len(parts))
	}
	if first := manifest.Layers[0]; first.MediaType != transfer.LayerMediaType {
		t.Errorf("first layer is a %s, want the tar", first.MediaType)
	}
	if got := parts[2].Annotations; got[transfer.AnnotationFilePath] != "big.bin" || got[transfer.AnnotationFileOffset] != "80" || got[transfer.AnnotationFileSize] != "100" {
		t.Errorf("third part's annotations = %v, want big.bin from 80 of 100", got)
	}

	pulledDir := t.TempDir()
	if _, err := pull.Pull(context.Background(), store, "model", pulledDir, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	restored := layout.ComponentLayer(pulledDir, modelComponent.PackageURL)
	got := readDir(t, restored)
	for path, want := range files {
		if got[path] != want {
			t.Errorf("%s = %q, want %q", path, got[path], want)
		}
	}
	if len(got) != len(files) {
		t.Errorf("restored %d files, want %d", len(got), len(files))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(restored, "big.bin"))
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Errorf("big.bin's mode = %v, %v; want 0755", info.Mode().Perm(), err)
		}
	}
}

// TestPushSharesLargeFiles covers what file parts are for: another
// package holding the same large file reuses its blobs.
func TestPushSharesLargeFiles(t *testing.T) {
	layerLimits(t, 16, 40)
	weights := strings.Repeat("shared weights ", 10)
	other := cdx.Component{
		Type:       cdx.ComponentTypeMachineLearningModel,
		Name:       "other",
		Version:    "2.0",
		PackageURL: "pkg:generic/other@2.0?download_url=https://example.com/other",
	}
	store := newStore(t)

	partDigests := map[string][]string{}
	for _, component := range []cdx.Component{modelComponent, other} {
		baseDir := t.TempDir()
		writeLayer(t, baseDir, component, map[string]string{
			"weights.bin": weights,
			"name.txt":    component.Name,
		})
		sbomHash := recordSBOM(t, baseDir, []cdx.Component{component})
		if _, err := Push(context.Background(), store, component.Name, baseDir, sbomHash, transfer.Options{Concurrency: 2}); err != nil {
			t.Fatalf("Push %s: %v", component.Name, err)
		}
		for _, layer := range manifestOf(t, store, component.Name).Layers {
			if layer.MediaType == transfer.FilePartMediaType {
				partDigests[component.Name] = append(partDigests[component.Name], layer.Digest.String())
			}
		}
	}
	if strings.Join(partDigests["model"], ",") != strings.Join(partDigests["other"], ",") || len(partDigests["model"]) == 0 {
		t.Errorf("part digests = %v, want the same blobs in both packages", partDigests)
	}
}

func TestPushEmptyComponent(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.MkdirAll(layout.ComponentLayer(baseDir, modelComponent.PackageURL), 0o755); err != nil {
		t.Fatal(err)
	}
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{modelComponent})
	store := newStore(t)

	if _, err := Push(context.Background(), store, "model", baseDir, sbomHash, transfer.Options{}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if layers := manifestOf(t, store, "model").Layers; len(layers) != 1 || layers[0].MediaType != transfer.LayerMediaType {
		t.Fatalf("layers = %v, want one empty tar", layers)
	}
	pulledDir := t.TempDir()
	if _, err := pull.Pull(context.Background(), store, "model", pulledDir, transfer.Options{}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if info, err := os.Stat(layout.ComponentLayer(pulledDir, modelComponent.PackageURL)); err != nil || !info.IsDir() {
		t.Errorf("component directory not restored: %v", err)
	}
}

// part describes a file part layer for craftPackage.
type part struct {
	path, mode     string
	size, offset   int64
	content        string
	tarOfFileNamed string
}

// craftPackage pushes a package of modelComponent whose layers are parts,
// annotated as given, as a hostile registry might serve.
func craftPackage(t *testing.T, store *oci.Store, parts []part) {
	t.Helper()
	ctx := context.Background()
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"machine-learning-model","name":"model","version":"1.0","purl":"` + modelComponent.PackageURL + `"}]}`)
	config, err := oras.PushBytes(ctx, store, "application/vnd.cyclonedx+json", sbom)
	if err != nil {
		t.Fatal(err)
	}

	var layers []ocispec.Descriptor
	for _, p := range parts {
		if p.tarOfFileNamed != "" {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, p.tarOfFileNamed), []byte(p.content), 0o644); err != nil {
				t.Fatal(err)
			}
			var buffer strings.Builder
			if err := transfer.WriteTar(dir, &buffer); err != nil {
				t.Fatal(err)
			}
			desc, err := oras.PushBytes(ctx, store, transfer.LayerMediaType, []byte(buffer.String()))
			if err != nil {
				t.Fatal(err)
			}
			desc.Annotations = map[string]string{transfer.AnnotationPurl: modelComponent.PackageURL}
			layers = append(layers, desc)
			continue
		}
		desc, err := oras.PushBytes(ctx, store, transfer.FilePartMediaType, []byte(p.content))
		if err != nil {
			t.Fatal(err)
		}
		desc.Annotations = map[string]string{
			transfer.AnnotationPurl:       modelComponent.PackageURL,
			transfer.AnnotationFilePath:   p.path,
			transfer.AnnotationFileMode:   p.mode,
			transfer.AnnotationFileSize:   strconv.FormatInt(p.size, 10),
			transfer.AnnotationFileOffset: strconv.FormatInt(p.offset, 10),
		}
		layers = append(layers, desc)
	}

	manifest, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, transfer.ArtifactType, oras.PackManifestOptions{
		ConfigDescriptor: &config,
		Layers:           layers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, manifest, "crafted"); err != nil {
		t.Fatal(err)
	}
}

func TestPullRejectsMalformedParts(t *testing.T) {
	for name, tc := range map[string]struct {
		parts []part
		want  string
	}{
		"escaping path": {
			parts: []part{{path: "../escape", mode: "0644", size: 3, content: "abc"}},
			want:  "outside its component",
		},
		"absolute path": {
			parts: []part{{path: "/etc/passwd", mode: "0644", size: 3, content: "abc"}},
			want:  "outside its component",
		},
		"gap": {
			parts: []part{
				{path: "f", mode: "0644", size: 6, offset: 0, content: "ab"},
				{path: "f", mode: "0644", size: 6, offset: 4, content: "ef"},
			},
			want: "don't cover it",
		},
		"short": {
			parts: []part{{path: "f", mode: "0644", size: 6, content: "abc"}},
			want:  "cover 3 of its 6 bytes",
		},
		"overlap": {
			parts: []part{
				{path: "f", mode: "0644", size: 4, offset: 0, content: "abc"},
				{path: "f", mode: "0644", size: 4, offset: 2, content: "cd"},
			},
			want: "don't cover it",
		},
		"conflicting modes": {
			parts: []part{
				{path: "f", mode: "0644", size: 4, offset: 0, content: "ab"},
				{path: "f", mode: "0755", size: 4, offset: 2, content: "cd"},
			},
			want: "disagree",
		},
		"bad mode": {
			parts: []part{{path: "f", mode: "rwx", size: 3, content: "abc"}},
			want:  "invalid file mode",
		},
		"tar overwrites a part": {
			parts: []part{
				{path: "f", mode: "0644", size: 3, content: "abc"},
				{tarOfFileNamed: "f", content: "evil"},
			},
			want: "unpack",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newStore(t)
			craftPackage(t, store, tc.parts)
			pulledDir := t.TempDir()

			_, err := pull.Pull(context.Background(), store, "crafted", pulledDir, transfer.Options{Concurrency: 2})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Pull = %v, want an error containing %q", err, tc.want)
			}
			if _, statErr := os.Stat(layout.ComponentLayer(pulledDir, modelComponent.PackageURL)); !os.IsNotExist(statErr) {
				t.Errorf("component directory restored despite the error: %v", statErr)
			}
		})
	}
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// recordLabels returns a ProgressFunc recording every label it's given.
func recordLabels(labels *[]string) transfer.ProgressFunc {
	var mutex sync.Mutex
	return func(label string, _ int64) io.WriteCloser {
		mutex.Lock()
		defer mutex.Unlock()
		*labels = append(*labels, label)
		return nopWriteCloser{}
	}
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(data []byte) (int, error) { return len(data), nil }
func (nopWriteCloser) Close() error                   { return nil }

// TestPushAndPullLabelPartsAlike covers each part's progress bar: named
// by its file and which part it is, the same way on push and pull.
func TestPushAndPullLabelPartsAlike(t *testing.T) {
	layerLimits(t, 16, 40)
	baseDir := t.TempDir()
	// No two parts alike: a part the store already has isn't pushed, so
	// gets no bar.
	var big strings.Builder
	for index := range 100 {
		big.WriteByte(byte('a' + index%26))
	}
	writeLayer(t, baseDir, modelComponent, map[string]string{
		"big.bin":   big.String(),
		"small.txt": "small",
	})
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{modelComponent})
	store := newStore(t)

	var pushed, pulled []string
	if _, err := Push(context.Background(), store, "model", baseDir, sbomHash, transfer.Options{Concurrency: 2, Progress: recordLabels(&pushed)}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, err := pull.Pull(context.Background(), store, "model", t.TempDir(), transfer.Options{Concurrency: 2, Progress: recordLabels(&pulled)}); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	partLabels := func(labels []string) []string {
		var parts []string
		for _, label := range labels {
			if strings.HasPrefix(label, "big.bin") {
				parts = append(parts, label)
			}
		}
		slices.Sort(parts)
		return parts
	}
	want := []string{
		"big.bin 1/3 " + modelComponent.PackageURL,
		"big.bin 2/3 " + modelComponent.PackageURL,
		"big.bin 3/3 " + modelComponent.PackageURL,
	}
	if got := partLabels(pushed); !slices.Equal(got, want) {
		t.Errorf("push labelled the parts %q, want %q", got, want)
	}
	if got := partLabels(pulled); !slices.Equal(got, want) {
		t.Errorf("pull labelled the parts %q, want %q", got, want)
	}
}

// TestPushAndPullSymlinks covers a symlink to a large file: the link
// travels in a tar and the file in parts, so pull may only check the link
// once every layer is in.
func TestPushAndPullSymlinks(t *testing.T) {
	layerLimits(t, 16, 40)
	baseDir := t.TempDir()
	weights := strings.Repeat("0123456789", 10)
	writeLayer(t, baseDir, modelComponent, map[string]string{"weights.bin": weights})
	dir := layout.ComponentLayer(baseDir, modelComponent.PackageURL)
	if err := os.Symlink("weights.bin", filepath.Join(dir, "model.bin")); err != nil {
		t.Skipf("can't create symlinks here: %v", err)
	}
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{modelComponent})
	store := newStore(t)

	if _, err := Push(context.Background(), store, "model", baseDir, sbomHash, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	pulledDir := t.TempDir()
	if _, err := pull.Pull(context.Background(), store, "model", pulledDir, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	restored := layout.ComponentLayer(pulledDir, modelComponent.PackageURL)
	if link, err := os.Readlink(filepath.Join(restored, "model.bin")); err != nil || link != "weights.bin" {
		t.Errorf("model.bin points to %q, %v; want weights.bin", link, err)
	}
	if data, err := os.ReadFile(filepath.Join(restored, "model.bin")); err != nil || string(data) != weights {
		t.Errorf("model.bin reads %d bytes, %v; want the weights", len(data), err)
	}
}
