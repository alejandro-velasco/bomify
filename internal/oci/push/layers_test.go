package push

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// layerLimits makes transfer.LargeFileSize and transfer.MaxTarSize
// small for a test.
func layerLimits(t *testing.T, largeFile, maxTar int64) {
	t.Helper()
	originalLarge, originalMax := transfer.LargeFileSize, transfer.MaxTarSize
	transfer.LargeFileSize, transfer.MaxTarSize = largeFile, maxTar
	t.Cleanup(func() { transfer.LargeFileSize, transfer.MaxTarSize = originalLarge, originalMax })
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

func TestPushGivesLargeFilesALayerEach(t *testing.T) {
	// Each small file takes 1024 bytes of a tar, so two fit in one.
	layerLimits(t, 16, 2100)
	baseDir := t.TempDir()
	files := map[string]string{
		"a.json":          "small file one.",
		"b.json":          "small file two.",
		"c.json":          "small file 3...",
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
	var tars, fileLayers []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		switch layer.MediaType {
		case transfer.LayerMediaType:
			tars = append(tars, layer)
		case transfer.FileMediaType:
			fileLayers = append(fileLayers, layer)
		}
	}
	// The small files in two tars, then each large file whole, by path.
	if len(tars) != 2 || len(fileLayers) != 2 {
		t.Fatalf("got %d tar and %d file layers, want 2 and 2", len(tars), len(fileLayers))
	}
	if first := manifest.Layers[0]; first.MediaType != transfer.LayerMediaType {
		t.Errorf("first layer is a %s, want a tar", first.MediaType)
	}
	big := fileLayers[0]
	// 0755, but where the file system keeps no such bits, what it has.
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	wantAnnotations := map[string]string{
		transfer.AnnotationPurl:     modelComponent.PackageURL,
		transfer.AnnotationFilePath: "big.bin",
		transfer.AnnotationFileMode: fmt.Sprintf("%04o", info.Mode().Perm()),
	}
	if !maps.Equal(big.Annotations, wantAnnotations) || big.Size != 100 {
		t.Errorf("big.bin's layer = %d bytes, %v; want 100 bytes, %v", big.Size, big.Annotations, wantAnnotations)
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

// TestPushSharesLargeFiles covers what file layers are for: another
// package holding the same large file reuses its blob.
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

	fileDigests := map[string][]string{}
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
			if layer.MediaType == transfer.FileMediaType {
				fileDigests[component.Name] = append(fileDigests[component.Name], layer.Digest.String())
			}
		}
	}
	if strings.Join(fileDigests["model"], ",") != strings.Join(fileDigests["other"], ",") || len(fileDigests["model"]) == 0 {
		t.Errorf("file digests = %v, want the same blob in both packages", fileDigests)
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

// craftedLayer describes a layer for craftPackage: a file layer, or with
// tarOfFileNamed, a tar of one file of that name, or with symlinkTo, a
// tar of a symlink at path to it.
type craftedLayer struct {
	path, mode     string
	content        string
	tarOfFileNamed string
	symlinkTo      string
}

// craftPackage pushes a package of modelComponent of layers, annotated as
// given, as a hostile registry might serve.
func craftPackage(t *testing.T, store *oci.Store, crafted []craftedLayer) {
	t.Helper()
	ctx := context.Background()
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"machine-learning-model","name":"model","version":"1.0","purl":"` + modelComponent.PackageURL + `"}]}`)
	config, err := oras.PushBytes(ctx, store, "application/vnd.cyclonedx+json", sbom)
	if err != nil {
		t.Fatal(err)
	}

	var layers []ocispec.Descriptor
	for _, p := range crafted {
		if p.symlinkTo != "" {
			var buffer bytes.Buffer
			tw := tar.NewWriter(&buffer)
			header := &tar.Header{
				Typeflag: tar.TypeSymlink,
				Name:     p.path,
				Linkname: p.symlinkTo,
				Mode:     0o777,
			}
			if err := tw.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			desc, err := oras.PushBytes(ctx, store, transfer.LayerMediaType, buffer.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			desc.Annotations = map[string]string{transfer.AnnotationPurl: modelComponent.PackageURL}
			layers = append(layers, desc)
			continue
		}
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
		desc, err := oras.PushBytes(ctx, store, transfer.FileMediaType, []byte(p.content))
		if err != nil {
			t.Fatal(err)
		}
		desc.Annotations = map[string]string{
			transfer.AnnotationPurl:     modelComponent.PackageURL,
			transfer.AnnotationFilePath: p.path,
			transfer.AnnotationFileMode: p.mode,
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

func TestPullRejectsMalformedFiles(t *testing.T) {
	for name, tc := range map[string]struct {
		layers []craftedLayer
		// want is what the error contains: any of its "|"-separated
		// alternatives, for layers whose order of restore decides.
		want string
	}{
		"escaping path": {
			layers: []craftedLayer{{path: "../escape", mode: "0644", content: "abc"}},
			want:   "outside its component",
		},
		"absolute path": {
			layers: []craftedLayer{{path: "/etc/passwd", mode: "0644", content: "abc"}},
			want:   "outside its component",
		},
		"one path twice": {
			layers: []craftedLayer{
				{path: "f", mode: "0644", content: "abc"},
				{path: "f", mode: "0644", content: "def"},
			},
			want: "two layers hold f",
		},
		"bad mode": {
			layers: []craftedLayer{{path: "f", mode: "rwx", content: "abc"}},
			want:   "invalid file mode",
		},
		"a tar and a file layer hold one file": {
			layers: []craftedLayer{
				{path: "f", mode: "0644", content: "abc"},
				{tarOfFileNamed: "f", content: "evil"},
			},
			want: "unpack|create f",
		},
		// The tar restores first, at a concurrency of 1: a file layer
		// mustn't follow its link out of the component.
		"a file layer through a symlink out": {
			layers: []craftedLayer{
				{path: "out", symlinkTo: ".."},
				{path: "out/evil", mode: "0644", content: "evil"},
			},
			want: "create out/evil|unpack",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newStore(t)
			craftPackage(t, store, tc.layers)
			pulledDir := t.TempDir()

			_, err := pull.Pull(context.Background(), store, "crafted", pulledDir, transfer.Options{Concurrency: 1})
			if err == nil || !containsAny(err.Error(), strings.Split(tc.want, "|")) {
				t.Fatalf("Pull = %v, want an error containing %q", err, tc.want)
			}
			if escaped := findFile(t, pulledDir, "evil"); escaped != "" {
				t.Errorf("a layer wrote %s", escaped)
			}
			if _, statErr := os.Stat(layout.ComponentLayer(pulledDir, modelComponent.PackageURL)); !os.IsNotExist(statErr) {
				t.Errorf("component directory restored despite the error: %v", statErr)
			}
		})
	}
}

// findFile returns the path of a file named name under dir, or "".
func findFile(t *testing.T, dir, name string) string {
	t.Helper()
	var found string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Name() == name && !entry.IsDir() {
			found = path
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// containsAny reports whether s contains any of substrings.
func containsAny(s string, substrings []string) bool {
	return slices.ContainsFunc(substrings, func(substring string) bool { return strings.Contains(s, substring) })
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

// TestPushAndPullLabelFilesAlike covers a large file's progress bar:
// named by its path, the same way on push and pull.
func TestPushAndPullLabelFilesAlike(t *testing.T) {
	layerLimits(t, 16, 40)
	baseDir := t.TempDir()
	writeLayer(t, baseDir, modelComponent, map[string]string{
		"big.bin":   strings.Repeat("0123456789", 10),
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

	fileLabels := func(labels []string) []string {
		var files []string
		for _, label := range labels {
			if strings.HasPrefix(label, "big.bin") {
				files = append(files, label)
			}
		}
		return files
	}
	want := []string{"big.bin " + modelComponent.PackageURL}
	if got := fileLabels(pushed); !slices.Equal(got, want) {
		t.Errorf("push labelled the file %q, want %q", got, want)
	}
	if got := fileLabels(pulled); !slices.Equal(got, want) {
		t.Errorf("pull labelled the file %q, want %q", got, want)
	}
}

// TestPushAndPullSymlinks covers a symlink to a large file: the link
// travels in a tar and the file as a layer of its own, so pull may only
// check the link once every layer is in.
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
