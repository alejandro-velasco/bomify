package push

import (
	"context"
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
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// dataComponent is packaged in bomify's own format: it's no model, and
// these tests give Push no packer.
var dataComponent = cdx.Component{
	Type:       cdx.ComponentTypeData,
	Name:       "data",
	Version:    "1.0",
	PackageURL: "pkg:generic/data@1.0?download_url=https://example.com/data",
}

// weightSize makes modelWeightSize, from which a model's file is a
// weight, size for a test.
func weightSize(t *testing.T, size int64) {
	t.Helper()
	original := modelWeightSize
	modelWeightSize = size
	t.Cleanup(func() { modelWeightSize = original })
}

func newStore(t *testing.T) *oci.Store {
	t.Helper()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	return store
}

// TestPushGivesEachFileALayer covers bomify's own format: a layer per
// file, by path, titled with it, whose files map entry keeps its mode.
func TestPushGivesEachFileALayer(t *testing.T) {
	baseDir := t.TempDir()
	files := map[string]string{
		"b.json":          "small file two.",
		"a.json":          "small file one.",
		"big.bin":         strings.Repeat("0123456789", 10),
		"nested/huge.bin": strings.Repeat("abcde", 10),
	}
	writeLayer(t, baseDir, dataComponent, files)
	executable := filepath.Join(layout.ComponentLayer(baseDir, dataComponent.PackageURL), "big.bin")
	if err := os.Chmod(executable, 0o755); err != nil {
		t.Fatal(err)
	}
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent})
	store := newStore(t)

	tagPackage(t, baseDir, "data", sbomHash)
	if _, err := Push(context.Background(), store, "data", baseDir, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	manifest := componentManifestOf(t, store, "data", dataComponent.PackageURL)
	var titles []string
	for _, layer := range manifest.Layers {
		title := layer.Annotations[ocispec.AnnotationTitle]
		titles = append(titles, title)
		wantAnnotations := map[string]string{
			transfer.AnnotationPurl: dataComponent.PackageURL,
			ocispec.AnnotationTitle: title,
		}
		if layer.MediaType != transfer.FileMediaType || !maps.Equal(layer.Annotations, wantAnnotations) || layer.Size != int64(len(files[title])) {
			t.Errorf("%s's layer = %+v, want its own bytes, annotated %v", title, layer, wantAnnotations)
		}
	}
	if want := []string{"a.json", "b.json", "big.bin", "nested/huge.bin"}; !slices.Equal(titles, want) {
		t.Errorf("layers = %v, want %v", titles, want)
	}

	_, pkg := fetchPackage(t, store, "data")
	mapped := filesOf(t, store, pkg, dataComponent.PackageURL)
	// 0755, but where the file system keeps no such bits, what it has.
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	big := slices.IndexFunc(mapped.Files, func(file transfer.FileBlob) bool { return file.Path == "big.bin" })
	if big < 0 || fs.FileMode(mapped.Files[big].Mode) != info.Mode().Perm() {
		t.Errorf("files map = %+v, want big.bin's mode", mapped.Files)
	}

	pulledDir := t.TempDir()
	if _, err := pull.Pull(context.Background(), store, "data", pulledDir, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	restored := layout.ComponentLayer(pulledDir, dataComponent.PackageURL)
	if got := readDir(t, restored); !mapsEqual(got, files) {
		t.Errorf("pulled %v, want %v", got, files)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(restored, "big.bin"))
		if err != nil || info.Mode().Perm() != 0o755 {
			t.Errorf("big.bin's mode = %v, %v; want 0755", info.Mode().Perm(), err)
		}
	}
}

// TestPushSharesFiles covers what a layer per file is for: another
// package holding the same file reuses its blob.
func TestPushSharesFiles(t *testing.T) {
	weights := strings.Repeat("shared weights ", 10)
	other := cdx.Component{
		Type:       cdx.ComponentTypeData,
		Name:       "other",
		Version:    "2.0",
		PackageURL: "pkg:generic/other@2.0?download_url=https://example.com/other",
	}
	store := newStore(t)

	weightDigests := map[string]string{}
	for _, component := range []cdx.Component{dataComponent, other} {
		baseDir := t.TempDir()
		writeLayer(t, baseDir, component, map[string]string{
			"weights.bin": weights,
			"name.txt":    component.Name,
		})
		sbomHash := recordSBOM(t, baseDir, []cdx.Component{component})
		tagPackage(t, baseDir, component.Name, sbomHash)
		if _, err := Push(context.Background(), store, component.Name, baseDir, transfer.Options{Concurrency: 2}); err != nil {
			t.Fatalf("Push %s: %v", component.Name, err)
		}
		for _, layer := range componentManifestOf(t, store, component.Name, component.PackageURL).Layers {
			if layer.Annotations[ocispec.AnnotationTitle] == "weights.bin" {
				weightDigests[component.Name] = layer.Digest.String()
			}
		}
	}
	if weightDigests["data"] != weightDigests["other"] || weightDigests["data"] == "" {
		t.Errorf("weights.bin digests = %v, want the same blob in both packages", weightDigests)
	}
}

// TestPushEmptyComponent covers a component with no files: the empty
// descriptor its one layer, as OCI suggests, and no files in the files
// map, from which pull still restores its directory.
func TestPushEmptyComponent(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.MkdirAll(layout.ComponentLayer(baseDir, dataComponent.PackageURL), 0o755); err != nil {
		t.Fatal(err)
	}
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent})
	store := newStore(t)

	tagPackage(t, baseDir, "data", sbomHash)
	if _, err := Push(context.Background(), store, "data", baseDir, transfer.Options{}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if layers := componentManifestOf(t, store, "data", dataComponent.PackageURL).Layers; len(layers) != 1 || layers[0].MediaType != ocispec.MediaTypeEmptyJSON {
		t.Fatalf("layers = %v, want the empty descriptor", layers)
	}
	_, pkg := fetchPackage(t, store, "data")
	if files := filesOf(t, store, pkg, dataComponent.PackageURL); files == nil || len(files.Files) != 0 {
		t.Errorf("files map = %+v, want the component, with no files", files)
	}
	pulledDir := t.TempDir()
	if _, err := pull.Pull(context.Background(), store, "data", pulledDir, transfer.Options{}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if info, err := os.Stat(layout.ComponentLayer(pulledDir, dataComponent.PackageURL)); err != nil || !info.IsDir() {
		t.Errorf("component directory not restored: %v", err)
	}
}

// TestPushRefusesSymlinks covers what no blob holds: push refuses a
// component with a symlink, whatever its format.
func TestPushRefusesSymlinks(t *testing.T) {
	for _, component := range []cdx.Component{dataComponent, modelComponent} {
		baseDir := t.TempDir()
		writeLayer(t, baseDir, component, map[string]string{"weights.bin": "weights"})
		dir := layout.ComponentLayer(baseDir, component.PackageURL)
		if err := os.Symlink("weights.bin", filepath.Join(dir, "model.bin")); err != nil {
			t.Skipf("can't create symlinks here: %v", err)
		}
		sbomHash := recordSBOM(t, baseDir, []cdx.Component{component})

		tagPackage(t, baseDir, "pkg", sbomHash)
		_, err := Push(context.Background(), newStore(t), "pkg", baseDir, transfer.Options{})
		if err == nil || !strings.Contains(err.Error(), "model.bin isn't a regular file") {
			t.Errorf("Push %s = %v, want the symlink refused", component.Name, err)
		}
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

// TestPushAndPullLabelLayersAlike covers a component's progress bars: one
// per layer, each naming the component but telling its layers apart,
// the same way on push and pull.
func TestPushAndPullLabelLayersAlike(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, dataComponent, map[string]string{
		"big.bin":   strings.Repeat("0123456789", 10),
		"small.txt": "small",
	})
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent})
	store := newStore(t)

	var pushed, pulled []string
	tagPackage(t, baseDir, "data", sbomHash)
	if _, err := Push(context.Background(), store, "data", baseDir, transfer.Options{Concurrency: 2, Progress: recordLabels(&pushed)}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, err := pull.Pull(context.Background(), store, "data", t.TempDir(), transfer.Options{Concurrency: 2, Progress: recordLabels(&pulled)}); err != nil {
		t.Fatalf("Pull: %v", err)
	}

	// Two layers, small.txt and big.bin.
	componentLabels := func(labels []string) []string {
		kept := slices.DeleteFunc(slices.Clone(labels), func(label string) bool {
			return !strings.HasSuffix(label, " "+dataComponent.PackageURL)
		})
		slices.Sort(kept)
		return slices.Compact(kept)
	}
	pushedLabels := componentLabels(pushed)
	if len(pushedLabels) != 2 {
		t.Errorf("push labelled the component's layers %q, want 2 distinct labels", pushedLabels)
	}
	if pulledLabels := componentLabels(pulled); !slices.Equal(pulledLabels, pushedLabels) {
		t.Errorf("pull labelled the component's layers %q, want push's %q", pulledLabels, pushedLabels)
	}
}

// countingStore is a store that records the most blobs it's had open for
// fetching at once, holding each one open a moment so fetches overlap.
type countingStore struct {
	*oci.Store
	mutex  sync.Mutex
	active int
	most   int
}

func (s *countingStore) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	rc, err := s.Store.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	s.mutex.Lock()
	s.active++
	s.most = max(s.most, s.active)
	s.mutex.Unlock()
	time.Sleep(20 * time.Millisecond)
	fetch := countedFetch{
		ReadCloser: rc,
		store:      s,
	}
	return &fetch, nil
}

// countedFetch is one of countingStore's open fetches.
type countedFetch struct {
	io.ReadCloser
	store *countingStore
}

func (f *countedFetch) Close() error {
	f.store.mutex.Lock()
	f.store.active--
	f.store.mutex.Unlock()
	return f.ReadCloser.Close()
}

// TestPullBoundsDownloads covers pull's concurrency: components restore at
// once, each downloading its layers at once, but no more than Concurrency
// layers download at a time in all.
func TestPullBoundsDownloads(t *testing.T) {
	baseDir := t.TempDir()
	var components []cdx.Component
	for _, name := range []string{"one", "two", "three"} {
		component := cdx.Component{
			Type:       cdx.ComponentTypeMachineLearningModel,
			Name:       name,
			Version:    "1.0",
			PackageURL: "pkg:generic/" + name + "@1.0",
		}
		// A file layer each.
		writeLayer(t, baseDir, component, map[string]string{
			"a.bin": strings.Repeat("a", 100) + name,
			"b.bin": strings.Repeat("b", 100) + name,
			"c.bin": strings.Repeat("c", 100) + name,
		})
		components = append(components, component)
	}
	sbomHash := recordSBOM(t, baseDir, components)
	store := countingStore{
		Store: newStore(t),
	}
	tagPackage(t, baseDir, "models", sbomHash)
	if _, err := Push(context.Background(), store.Store, "models", baseDir, transfer.Options{Concurrency: 4}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	const concurrency = 2
	if _, err := pull.Pull(context.Background(), &store, "models", t.TempDir(), transfer.Options{Concurrency: concurrency}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if store.most > concurrency {
		t.Errorf("pull downloaded %d blobs at once, want at most %d", store.most, concurrency)
	}
	if store.most < concurrency {
		t.Errorf("pull downloaded at most %d blobs at once, want %d: the test isn't overlapping downloads", store.most, concurrency)
	}
}

// TestOrasPullsAComponent covers what bomify's own format and ModelPack
// are annotated for: `oras pull` of a component's manifest writes out its
// files as build pulled them, each at its path.
func TestOrasPullsAComponent(t *testing.T) {
	baseDir := t.TempDir()
	dataFiles := map[string]string{
		"LICENSE":         "the license",
		"docs/README.md":  "a nested small file",
		"nested/huge.bin": strings.Repeat("abcde", 10),
	}
	modelFiles := map[string]string{
		"config.json":         "{}",
		"weights/model.bin":   strings.Repeat("0123456789", 10),
		"tokenizer/vocab.txt": "vocab",
	}
	writeLayer(t, baseDir, dataComponent, dataFiles)
	writeLayer(t, baseDir, modelComponent, modelFiles)
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent, modelComponent})
	store := newStore(t)
	tagPackage(t, baseDir, "pkg", sbomHash)
	if _, err := Push(context.Background(), store, "pkg", baseDir, transfer.Options{}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	_, pkg := fetchPackage(t, store, "pkg")
	for component, want := range map[cdx.Component]map[string]string{dataComponent: dataFiles, modelComponent: modelFiles} {
		manifest := componentEntry(t, pkg, component.PackageURL)
		if got := orasPull(t, store, manifest); !mapsEqual(got, want) {
			t.Errorf("oras pull of %s wrote %v, want %v", component.Name, got, want)
		}
	}
}

// orasPull pulls manifest from store as `oras pull` does, into a new
// directory, returning what it wrote.
func orasPull(t *testing.T, store *oci.Store, manifest ocispec.Descriptor) map[string]string {
	t.Helper()
	dir := t.TempDir()
	fileStore, err := file.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fileStore.Close()
	if err := oras.CopyGraph(context.Background(), store, fileStore, manifest, oras.DefaultCopyGraphOptions); err != nil {
		t.Fatalf("oras pull %s: %v", manifest.Digest, err)
	}
	return readDir(t, dir)
}
