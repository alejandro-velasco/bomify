package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
)

// pushJSON pushes v, as JSON of mediaType, to store, returning its
// descriptor.
func pushJSON(t *testing.T, store *memory.Store, mediaType string, v any) ocispec.Descriptor {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return pushData(t, store, mediaType, data)
}

// pushData pushes data, of mediaType, to store, returning its descriptor.
func pushData(t *testing.T, store *memory.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	if err := store.Push(context.Background(), desc, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	return desc
}

// sbomManifest pushes an SBOM manifest whose first layer is files, as
// the files map, to store.
func sbomManifest(t *testing.T, store *memory.Store, files any) ocispec.Descriptor {
	t.Helper()
	filesDesc := pushJSON(t, store, FilesMediaType, files)
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SBOMArtifactType,
		Config:       ocispec.DescriptorEmptyJSON,
		Layers:       []ocispec.Descriptor{filesDesc},
	}
	desc := pushJSON(t, store, ocispec.MediaTypeImageManifest, manifest)
	desc.ArtifactType = SBOMArtifactType
	return desc
}

// packageIndex pushes an index of entries, of artifactType, to store.
func packageIndex(t *testing.T, store *memory.Store, artifactType string, entries ...ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	index := ocispec.Index{
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: artifactType,
		Manifests:    entries,
	}
	index.SchemaVersion = 2
	return pushJSON(t, store, ocispec.MediaTypeImageIndex, index)
}

// component is an index entry for a component manifest of purl.
func component(purl string) ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageManifest,
		Digest:      digest.FromString(purl),
		Size:        2,
		Annotations: map[string]string{AnnotationPurl: purl},
	}
	return desc
}

func TestFetchPackage(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	sbom := sbomManifest(t, store, Files{})
	// Neither the SBOM nor a component: ignored.
	other := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("other"), Size: 2}
	index := packageIndex(t, store, ArtifactType, sbom, component("pkg:oci/a@1"), other, component("pkg:oci/b@2"))

	pkg, err := FetchPackage(ctx, store, index)

	if err != nil {
		t.Fatalf("FetchPackage: %v", err)
	}
	if pkg.SBOM.Digest != sbom.Digest || pkg.SBOMManifest.ArtifactType != SBOMArtifactType {
		t.Errorf("SBOM = %v, manifest %+v, want %v", pkg.SBOM.Digest, pkg.SBOMManifest, sbom.Digest)
	}
	if len(pkg.Components) != 2 || pkg.Components[0].Annotations[AnnotationPurl] != "pkg:oci/a@1" || pkg.Components[1].Annotations[AnnotationPurl] != "pkg:oci/b@2" {
		t.Errorf("Components = %v, want a then b", pkg.Components)
	}
}

func TestFetchPackageRejects(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	sbom := sbomManifest(t, store, Files{})
	missingSBOM := sbom
	missingSBOM.Digest = digest.FromString("missing")
	huge := packageIndex(t, store, ArtifactType, sbom)
	huge.Size = maxManifestSize + 1

	for name, test := range map[string]struct {
		desc ocispec.Descriptor
		want string
	}{
		"a manifest":           {desc: sbom, want: "not an index"},
		"another artifact":     {desc: packageIndex(t, store, "application/vnd.other", sbom), want: "isn't a bomify package"},
		"no SBOM":              {desc: packageIndex(t, store, ArtifactType, component("pkg:oci/a@1")), want: "no SBOM manifest"},
		"two SBOMs":            {desc: packageIndex(t, store, ArtifactType, sbom, sbom), want: "more than one SBOM manifest"},
		"an SBOM it can't get": {desc: packageIndex(t, store, ArtifactType, missingSBOM), want: "fetch SBOM manifest"},
		"an index it can't get": {
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("gone"), Size: 2},
			want: "fetch index",
		},
		"an index too large": {desc: huge, want: "larger than"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := FetchPackage(ctx, store, test.desc)

			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("FetchPackage = %v, want an error containing %q", err, test.want)
			}
		})
	}
}

// rawFetcher fetches its bytes, whatever is asked for, as a registry
// might serve a blob that isn't what its descriptor says.
type rawFetcher []byte

func (f rawFetcher) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f)), nil
}

func TestFetchPackageRejectsAnIndexNotJSON(t *testing.T) {
	data := []byte("not json")
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageIndex,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}

	_, err := FetchPackage(context.Background(), rawFetcher(data), desc)

	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("FetchPackage = %v, want a parse error", err)
	}
}

// fileBlob is a file of path in a files map, with a sha256 digest.
func fileBlob(path string, size int64) FileBlob {
	blob := FileBlob{
		Path:      path,
		Mode:      0o644,
		MediaType: FileMediaType,
		Digest:    digest.FromString(path),
		Size:      size,
	}
	return blob
}

func TestFetchFiles(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	want := Files{Components: []ComponentFiles{
		{Purl: "pkg:oci/a@1", Files: []FileBlob{fileBlob("bin/a", 3), fileBlob("etc/a.conf", 4)}},
		{Purl: "pkg:oci/b@2", Files: []FileBlob{fileBlob("b", 5)}},
	}}
	sbom := sbomManifest(t, store, want)
	pkg, err := FetchPackage(ctx, store, packageIndex(t, store, ArtifactType, sbom))
	if err != nil {
		t.Fatal(err)
	}

	files, err := FetchFiles(ctx, store, pkg)

	if err != nil {
		t.Fatalf("FetchFiles: %v", err)
	}
	a, ok := files.Component("pkg:oci/a@1")
	if !ok || len(a.Files) != 2 || a.Size() != 7 {
		t.Errorf("Component(a) = %+v, %v, want its two files of 7 bytes", a, ok)
	}
	if desc := a.Files[0].Descriptor(); desc.Digest != digest.FromString("bin/a") || desc.Size != 3 || desc.MediaType != FileMediaType {
		t.Errorf("Descriptor = %+v, want bin/a's blob", desc)
	}
	if _, ok := files.Component("pkg:oci/missing@1"); ok {
		t.Error("Component(missing) found one")
	}
}

func TestFetchFilesRejects(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	md5 := fileBlob("f", 1)
	md5.Digest = digest.Digest("md5:d41d8cd98f00b204e9800998ecf8427e")
	invalid := fileBlob("f", 1)
	invalid.Digest = digest.Digest("sha256:short")
	files := func(components ...ComponentFiles) Files { return Files{Components: components} }

	for name, test := range map[string]struct {
		files any
		want  string
	}{
		"a component twice":     {files: files(ComponentFiles{Purl: "pkg:oci/a@1"}, ComponentFiles{Purl: "pkg:oci/a@1"}), want: "more than once"},
		"a component, no purl":  {files: files(ComponentFiles{}), want: "without a purl"},
		"a file outside":        {files: files(ComponentFiles{Purl: "p", Files: []FileBlob{fileBlob("../f", 1)}}), want: "outside its component"},
		"a file twice":          {files: files(ComponentFiles{Purl: "p", Files: []FileBlob{fileBlob("f", 1), fileBlob("f", 1)}}), want: "more than once"},
		"a file's md5 digest":   {files: files(ComponentFiles{Purl: "p", Files: []FileBlob{md5}}), want: "isn't sha256"},
		"a file's short digest": {files: files(ComponentFiles{Purl: "p", Files: []FileBlob{invalid}}), want: "isn't sha256"},
		"a map not JSON":        {files: "not a files map", want: "fetch files map"},
	} {
		t.Run(name, func(t *testing.T) {
			pkg := &Package{SBOM: ocispec.Descriptor{Digest: digest.FromString(name)}}
			pkg.SBOMManifest.Layers = []ocispec.Descriptor{pushJSON(t, store, FilesMediaType, test.files)}

			_, err := FetchFiles(ctx, store, pkg)

			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("FetchFiles = %v, want an error containing %q", err, test.want)
			}
		})
	}

	t.Run("no files map", func(t *testing.T) {
		for _, layers := range [][]ocispec.Descriptor{nil, {pushData(t, store, FileMediaType, []byte("f"))}} {
			pkg := &Package{}
			pkg.SBOMManifest.Layers = layers

			if _, err := FetchFiles(ctx, store, pkg); err == nil || !strings.Contains(err.Error(), "no files map") {
				t.Errorf("FetchFiles of layers %v = %v, want no files map", layers, err)
			}
		}
	})
}

func TestLabel(t *testing.T) {
	if got := Label("pkg:oci/a@1", "abc"); got != "pkg:oci/a@1" {
		t.Errorf("Label with a purl = %q, want the purl", got)
	}
	if got := Label("", "abc"); got != "abc" {
		t.Errorf("Label without a purl = %q, want the hash", got)
	}
}

func TestWithDefaults(t *testing.T) {
	defaulted := Options{Concurrency: -2}.WithDefaults()
	if defaulted.Concurrency != 1 || defaulted.Progress == nil {
		t.Errorf("WithDefaults() = concurrency %d, progress set %v, want 1 and set", defaulted.Concurrency, defaulted.Progress != nil)
	}

	opened := 0
	progress := func(string, int64) io.WriteCloser {
		opened++
		return discardWriteCloser{}
	}
	kept := Options{Concurrency: 4, Progress: progress}.WithDefaults()
	kept.Progress("x", 1)
	if kept.Concurrency != 4 || opened != 1 {
		t.Errorf("WithDefaults() = concurrency %d, progress called %d times, want what was set", kept.Concurrency, opened)
	}
}
