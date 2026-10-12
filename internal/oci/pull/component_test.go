package pull

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// fixtureComponent is a component of pushPackage's package, with the files
// its layers carry: each path, "/"-separated, to its content.
type fixtureComponent struct {
	component cdx.Component
	files     map[string]string
}

// pushPackage records and pushes a package of components, as `bomify
// build` and `bomify push` would, and returns the store to pull it from
// and the tag it's under.
func pushPackage(t *testing.T, components []fixtureComponent) (store *oci.Store, tag string) {
	t.Helper()

	sourceDir := t.TempDir()
	var sbomComponents []cdx.Component
	for _, fixture := range components {
		componentDir := layout.ComponentLayer(sourceDir, fixture.component.PackageURL)
		for path, content := range fixture.files {
			destination := filepath.Join(componentDir, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
				t.Fatalf("mkdir for %s: %v", path, err)
			}
			if err := os.WriteFile(destination, []byte(content), 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		}
		sbomComponents = append(sbomComponents, fixture.component)
	}

	sbomBytes, err := json.Marshal(struct {
		BOMFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		Version     int             `json:"version"`
		Components  []cdx.Component `json:"components"`
	}{"CycloneDX", "1.5", 1, sbomComponents})
	if err != nil {
		t.Fatalf("marshal sbom fixture: %v", err)
	}
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}
	sbomHash, _, err := build.RecordManifest(sourceDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err = oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	tag = "test"
	if _, err := push.Push(context.Background(), store, tag, sourceDir, sbomHash, transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	return store, tag
}

func modelComponent(name, version string) cdx.Component {
	return cdx.Component{
		Type:       cdx.ComponentTypeMachineLearningModel,
		Name:       name,
		Version:    version,
		PackageURL: "pkg:huggingface/org/" + name + "@" + version,
	}
}

// twoComponents is a package of a model with a subdirectory, and a
// single-file one.
func twoComponents() []fixtureComponent {
	return []fixtureComponent{
		{
			component: modelComponent("alpha", "1"),
			files: map[string]string{
				"config.json":         `{"a": 1}`,
				"onnx/model.onnx":     "alpha weights",
				"onnx/more/tail.json": "tail",
			},
		},
		{
			component: modelComponent("beta", "2"),
			files: map[string]string{
				"weights.bin": "beta weights",
			},
		},
	}
}

// readTree returns every file under dir, as its "/"-separated path to its
// content, and fails the test on anything else, such as a leftover
// staging directory, which would show up as a file.
func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		tree[filepath.ToSlash(relative)] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("read tree %s: %v", dir, err)
	}
	return tree
}

func assertTree(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	got := readTree(t, dir)
	if len(got) != len(want) {
		t.Errorf("%s holds %d files, want %d: got %v", dir, len(got), len(want), got)
	}
	for path, content := range want {
		if got[path] != content {
			t.Errorf("%s: content = %q, want %q", path, got[path], content)
		}
	}
}

func TestComponentsListsEachWithItsLayers(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())

	listed, err := Components(context.Background(), store, tag)
	if err != nil {
		t.Fatalf("Components() error = %v", err)
	}

	if len(listed) != 2 {
		t.Fatalf("Components() listed %d components, want 2: %v", len(listed), listed)
	}
	for index, wantName := range []string{"alpha", "beta"} {
		if listed[index].Component.Name != wantName {
			t.Errorf("component %d = %q, want %q (the SBOM's order)", index, listed[index].Component.Name, wantName)
		}
		if listed[index].Layers != 1 {
			t.Errorf("%s: layers = %d, want 1 (small files share one tar)", wantName, listed[index].Layers)
		}
		if listed[index].Size <= 0 {
			t.Errorf("%s: size = %d, want its layers' bytes", wantName, listed[index].Size)
		}
	}
	if listed[0].Size <= listed[1].Size {
		t.Errorf("alpha (3 files) = %d bytes, beta (1 file) = %d: want alpha larger", listed[0].Size, listed[1].Size)
	}
}

func TestComponentsUnknownReference(t *testing.T) {
	store, _ := pushPackage(t, twoComponents())

	if _, err := Components(context.Background(), store, "missing"); err == nil {
		t.Error("Components() of an unknown reference succeeded")
	}
}

func TestPullComponentRestoresOnlyThatComponent(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())
	dir := filepath.Join(t.TempDir(), "models", "alpha")

	result, err := PullComponent(context.Background(), store, tag, "alpha", intoDir(dir, false), transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("PullComponent() error = %v", err)
	}

	assertTree(t, dir, map[string]string{
		"config.json":         `{"a": 1}`,
		"onnx/model.onnx":     "alpha weights",
		"onnx/more/tail.json": "tail",
	})
	if result.Component.PackageURL != "pkg:huggingface/org/alpha@1" {
		t.Errorf("result component = %q, want alpha's purl", result.Component.PackageURL)
	}
	if result.Dir != dir {
		t.Errorf("result dir = %q, want %q", result.Dir, dir)
	}
	if !strings.HasPrefix(result.ManifestDigest, "sha256:") {
		t.Errorf("manifest digest = %q, want sha256:...", result.ManifestDigest)
	}
	if result.Layers != 1 {
		t.Errorf("layers = %d, want 1", result.Layers)
	}
}

func TestPullComponentNeverFetchesOtherComponentsLayers(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())
	listed, err := Components(context.Background(), store, tag)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := oras.Resolve(context.Background(), store, tag, oras.DefaultResolveOptions)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := fetchManifest(context.Background(), store, desc)
	if err != nil {
		t.Fatal(err)
	}
	betaLayers := componentLayers(manifest.Layers, listed[1].Component.PackageURL)
	if len(betaLayers) != 1 {
		t.Fatalf("beta has %d layers, want 1", len(betaLayers))
	}

	// A target that fails on beta's layer shows alpha's pull never asks for it.
	target := failingTarget{
		ReadOnlyTarget: store,
		fails: func(desc ocispec.Descriptor) bool {
			return desc.Digest == betaLayers[0].Digest
		},
	}
	dir := filepath.Join(t.TempDir(), "alpha")
	if _, err := PullComponent(context.Background(), target, tag, "alpha", intoDir(dir, false), transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("PullComponent() asked for another component's layer: %v", err)
	}
}

func TestPullComponentSelectors(t *testing.T) {
	components := append(twoComponents(), fixtureComponent{
		component: modelComponent("beta", "3"),
		files:     map[string]string{"weights.bin": "beta three"},
	})
	store, tag := pushPackage(t, components)

	for _, test := range []struct {
		name     string
		selector string
		want     string
		wantErr  error
	}{
		{name: "by purl", selector: "pkg:huggingface/org/beta@3", want: "beta three"},
		{name: "by name and version", selector: "beta@2", want: "beta weights"},
		{name: "by a name only one has", selector: "alpha", want: ""},
		{name: "a name two share", selector: "beta", wantErr: ErrAmbiguousComponent},
		{name: "no such component", selector: "gamma", wantErr: ErrNoComponent},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "out")
			_, err := PullComponent(context.Background(), store, tag, test.selector, intoDir(dir, false), transfer.Options{Concurrency: 1})
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("PullComponent(%q) error = %v, want %v", test.selector, err, test.wantErr)
				}
				if !strings.Contains(err.Error(), strconv.Quote(test.selector)) {
					t.Errorf("error = %q, want it to name %q", err, test.selector)
				}
				// The package's components may be many, so the error lists none.
				if strings.Contains(err.Error(), "pkg:") {
					t.Errorf("error = %q, want no purls in it", err)
				}
				if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
					t.Errorf("a failed pull left %s behind", dir)
				}
				return
			}
			if err != nil {
				t.Fatalf("PullComponent(%q) error = %v", test.selector, err)
			}
			if test.want != "" {
				if got := readTree(t, dir)["weights.bin"]; got != test.want {
					t.Errorf("weights.bin = %q, want %q", got, test.want)
				}
			}
		})
	}
}

func TestSelectComponentPrefersAPurlOverEarlierNames(t *testing.T) {
	// A component whose name is another's purl, listed first: the purl
	// still names the other.
	nameMatch := PackageComponent{Component: cdx.Component{Name: "pkg:generic/tool@1", PackageURL: "pkg:generic/other@1"}}
	purlMatch := PackageComponent{Component: cdx.Component{Name: "tool", PackageURL: "pkg:generic/tool@1"}}

	selected, err := selectComponent([]PackageComponent{nameMatch, purlMatch}, "pkg:generic/tool@1")

	if err != nil {
		t.Fatalf("selectComponent() error = %v", err)
	}
	if selected.Component.Name != "tool" {
		t.Errorf("selected %q, want the component whose purl matched", selected.Component.Name)
	}
}

// intoDir is the ComponentOptions of a pull into dir, replacing what it
// holds if replace is set.
func intoDir(dir string, replace bool) ComponentOptions {
	into := ComponentOptions{
		Dir:     dir,
		Replace: replace,
	}
	return into
}

func TestPullComponentRefusesADirectoryThatIsNotEmpty(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(keep, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := PullComponent(context.Background(), store, tag, "alpha", intoDir(dir, false), transfer.Options{Concurrency: 1})
	if err == nil || !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("PullComponent() into a non-empty directory error = %v, want \"is not empty\"", err)
	}
	assertTree(t, dir, map[string]string{"keep.txt": "mine"})

	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = PullComponent(context.Background(), store, tag, "alpha", intoDir(notDir, false), transfer.Options{Concurrency: 1})
	if err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("PullComponent() onto a file error = %v, want \"is not a directory\"", err)
	}
}

func TestPullComponentReplacesWhatTheDirectoryHeld(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "old", "weights.bin"), []byte("old weights"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := PullComponent(context.Background(), store, tag, "beta", intoDir(dir, true), transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("PullComponent() with replace error = %v", err)
	}

	assertTree(t, dir, map[string]string{"weights.bin": "beta weights"})
}

func TestPullComponentFailedReplaceKeepsTheOldFiles(t *testing.T) {
	// An update that can't finish its download leaves the old version.
	store, tag := pushPackage(t, twoComponents())
	failLayers := failingTarget{
		ReadOnlyTarget: store,
		fails: func(desc ocispec.Descriptor) bool {
			return desc.MediaType == transfer.LayerMediaType || desc.MediaType == transfer.FilePartMediaType
		},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "weights.bin"), []byte("old weights"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := PullComponent(context.Background(), failLayers, tag, "beta", intoDir(dir, true), transfer.Options{Concurrency: 1}); err == nil {
		t.Fatal("PullComponent() with replace succeeded with failing layers")
	}

	assertTree(t, dir, map[string]string{"weights.bin": "old weights"})
}

func TestPullComponentReplaceStillRefusesAFile(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := PullComponent(context.Background(), store, tag, "beta", intoDir(file, true), transfer.Options{Concurrency: 1})

	if err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("PullComponent() with replace onto a file error = %v, want \"is not a directory\"", err)
	}
}

func TestPullComponentFillsAnExistingEmptyDirectory(t *testing.T) {
	// A volume mounted in a container is an existing, empty directory.
	store, tag := pushPackage(t, twoComponents())
	dir := t.TempDir()

	if _, err := PullComponent(context.Background(), store, tag, "beta", intoDir(dir, false), transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("PullComponent() error = %v", err)
	}

	assertTree(t, dir, map[string]string{"weights.bin": "beta weights"})
}

func TestPullComponentFailedVerifyWritesNothing(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())
	dir := filepath.Join(t.TempDir(), "alpha")
	verifyErr := errors.New("not signed")
	opts := transfer.Options{
		Concurrency: 1,
		Verify: func(context.Context, oras.ReadOnlyTarget, string, ocispec.Descriptor) error {
			return verifyErr
		},
	}

	_, err := PullComponent(context.Background(), store, tag, "alpha", intoDir(dir, false), opts)

	if !errors.Is(err, verifyErr) {
		t.Fatalf("PullComponent() error = %v, want it to wrap %v", err, verifyErr)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("a pull that failed verification left %s behind", dir)
	}
}

func TestPullComponentFailedFetchLeavesTheDirectoryAsItWas(t *testing.T) {
	store, tag := pushPackage(t, twoComponents())
	failLayers := failingTarget{
		ReadOnlyTarget: store,
		fails: func(desc ocispec.Descriptor) bool {
			return desc.MediaType == transfer.LayerMediaType || desc.MediaType == transfer.FilePartMediaType
		},
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := PullComponent(context.Background(), failLayers, tag, "alpha", intoDir(missing, false), transfer.Options{Concurrency: 1}); err == nil {
		t.Fatal("PullComponent() succeeded with failing layers")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a failed pull left the directory it would have created: %v", err)
	}

	empty := t.TempDir()
	if _, err := PullComponent(context.Background(), failLayers, tag, "alpha", intoDir(empty, false), transfer.Options{Concurrency: 1}); err == nil {
		t.Fatal("PullComponent() into an existing directory succeeded with failing layers")
	}
	assertTree(t, empty, map[string]string{})
	entries, err := os.ReadDir(empty)
	if err != nil || len(entries) != 0 {
		t.Errorf("a failed pull left %v (err %v) in an existing empty directory", entries, err)
	}
}

func TestPullComponentLargeFileParts(t *testing.T) {
	// A file at least LargeFileSize long travels as parts, each its own
	// layer, written back at their offsets.
	previous := transfer.LargeFileSize
	transfer.LargeFileSize = 1024
	t.Cleanup(func() { transfer.LargeFileSize = previous })
	big := strings.Repeat("0123456789abcdef", 300) // 4800 bytes
	store, tag := pushPackage(t, []fixtureComponent{
		{
			component: modelComponent("big", "1"),
			files: map[string]string{
				"small.json":        "{}",
				"shards/model.bin":  big,
				"shards/model2.bin": big + "!",
			},
		},
	})
	dir := filepath.Join(t.TempDir(), "big")

	result, err := PullComponent(context.Background(), store, tag, "big", intoDir(dir, false), transfer.Options{Concurrency: 3})
	if err != nil {
		t.Fatalf("PullComponent() error = %v", err)
	}

	assertTree(t, dir, map[string]string{
		"small.json":        "{}",
		"shards/model.bin":  big,
		"shards/model2.bin": big + "!",
	})
	if result.Layers < 3 {
		t.Errorf("layers = %d, want a tar and parts of the large files", result.Layers)
	}
}

func TestWriteIntoMovesOnlyTheFilesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	write := func(stageDir string) (string, error) {
		filesDir := filepath.Join(stageDir, "data", "files")
		if err := os.MkdirAll(filepath.Join(filesDir, "sub"), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(filesDir, "sub", "a.txt"), []byte("a"), 0o644); err != nil {
			return "", err
		}
		// Scratch data beside the files, which writeInto throws away.
		if err := os.WriteFile(filepath.Join(stageDir, "data", "record.json"), []byte("{}"), 0o644); err != nil {
			return "", err
		}
		return filesDir, nil
	}

	if err := writeInto(dir, false, write); err != nil {
		t.Fatalf("writeInto() error = %v", err)
	}

	assertTree(t, dir, map[string]string{"sub/a.txt": "a"})
}

func TestWriteIntoFailureRemovesItsWork(t *testing.T) {
	writeErr := errors.New("disk full")
	write := func(stageDir string) (string, error) {
		if err := os.WriteFile(filepath.Join(stageDir, "partial.bin"), []byte("half"), 0o644); err != nil {
			return "", err
		}
		return "", writeErr
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if err := writeInto(missing, false, write); !errors.Is(err, writeErr) {
		t.Fatalf("writeInto() error = %v, want %v", err, writeErr)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a failed write left the directory it created: %v", err)
	}

	empty := t.TempDir()
	if err := writeInto(empty, false, write); !errors.Is(err, writeErr) {
		t.Fatalf("writeInto() error = %v, want %v", err, writeErr)
	}
	entries, err := os.ReadDir(empty)
	if err != nil || len(entries) != 0 {
		t.Errorf("a failed write left %v (err %v) in an existing directory", entries, err)
	}
}

// failingTarget is a target whose fetches of the descriptors fails selects
// fail, to check what a pull never asks for, or leaves behind when it
// can't finish.
type failingTarget struct {
	oras.ReadOnlyTarget
	fails func(desc ocispec.Descriptor) bool
}

func (f failingTarget) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	if f.fails(desc) {
		return nil, errors.New("fetch refused: " + desc.Digest.String())
	}
	return f.ReadOnlyTarget.Fetch(ctx, desc)
}
