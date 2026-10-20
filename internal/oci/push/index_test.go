package push

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	modelspec "github.com/modelpack/model-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// The components fakePacker packs: imageComponent as the image in the OCI
// image layout in its directory, as bomify-plugin-oci packs one, and
// chartComponent as an artifact whose one layer is its archive, with a
// config and manifest the pack builds, as bomify-plugin-helm packs a
// chart. modelComponent it leaves to Push, as ModelPack.
var (
	imageComponent = cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "image",
		Version:    "1.0",
		PackageURL: "pkg:oci/image@1.0",
	}
	chartComponent = cdx.Component{
		Type:       cdx.ComponentTypeApplication,
		Name:       "chart",
		Version:    "1.0",
		PackageURL: "pkg:helm/chart@1.0",
	}
	modelComponent = cdx.Component{
		Type:       cdx.ComponentTypeMachineLearningModel,
		Name:       "model",
		Version:    "1.0",
		PackageURL: "pkg:huggingface/org/model@2db69c1c3e91a05d2c64a3185acfbaf36f744e25",
	}
)

// The media types fakePacker's chart artifact has, Helm's.
const (
	chartConfigMediaType = "application/vnd.cncf.helm.config.v1+json"
	chartLayerMediaType  = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
)

// fakePacker is a transfer.Packer packing imageComponent and
// chartComponent (see packLayout and packArchive), and nothing else.
func fakePacker(_ context.Context, component cdx.Component, dir string) (*pluginlib.PackResult, error) {
	switch component.PackageURL {
	case imageComponent.PackageURL:
		return packLayout(dir)
	case chartComponent.PackageURL:
		return packArchive(dir)
	default:
		return &pluginlib.PackResult{}, nil
	}
}

// packLayout packs the one image of the OCI image layout in dir as it is:
// its manifest, config, and layers, each the layout's own file.
func packLayout(dir string) (*pluginlib.PackResult, error) {
	data, err := os.ReadFile(filepath.Join(dir, ocispec.ImageIndexFile))
	if err != nil {
		return nil, err
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}
	image := index.Manifests[0]
	blobPath := func(desc ocispec.Descriptor) string {
		return filepath.Join(dir, ocispec.ImageBlobsDir, desc.Digest.Algorithm().String(), desc.Digest.Encoded())
	}
	blobOf := func(desc ocispec.Descriptor) pluginlib.PackedBlob {
		blob := pluginlib.PackedBlob{
			MediaType: desc.MediaType,
			Digest:    desc.Digest.String(),
			Size:      desc.Size,
			Path:      blobPath(desc),
		}
		return blob
	}
	manifestData, err := os.ReadFile(blobPath(image))
	if err != nil {
		return nil, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, err
	}

	manifestBlob := blobOf(image)
	blobs := []pluginlib.PackedBlob{blobOf(manifest.Config)}
	for _, layer := range manifest.Layers {
		blobs = append(blobs, blobOf(layer))
	}
	result := pluginlib.PackResult{
		Manifest: &manifestBlob,
		Blobs:    blobs,
	}
	return &result, nil
}

// packArchive packs dir's chart.tgz as an artifact of one layer, its
// config and manifest inline.
func packArchive(dir string) (*pluginlib.PackResult, error) {
	archivePath := filepath.Join(dir, "chart.tgz")
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, err
	}
	layer := pluginlib.PackedBlob{
		MediaType: chartLayerMediaType,
		Digest:    digest.FromBytes(archive).String(),
		Size:      int64(len(archive)),
		Path:      archivePath,
	}
	config := pluginlib.InlineBlob(chartConfigMediaType, []byte(`{"name":"chart","version":"1.0"}`))
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		Config:    descriptorOf(config),
		Layers:    []ocispec.Descriptor{descriptorOf(layer)},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	manifestBlob := pluginlib.InlineBlob(ocispec.MediaTypeImageManifest, manifestData)
	result := pluginlib.PackResult{
		Manifest: &manifestBlob,
		Blobs:    []pluginlib.PackedBlob{config, layer},
	}
	return &result, nil
}

// descriptorOf returns blob's descriptor.
func descriptorOf(blob pluginlib.PackedBlob) ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType: blob.MediaType,
		Digest:    digest.Digest(blob.Digest),
		Size:      blob.Size,
	}
	return desc
}

// writeImageLayout writes an image, of one layer, into component's
// directory under baseDir as an OCI image layout, as bomify-plugin-oci
// pulls one, returning the image's manifest.
func writeImageLayout(t *testing.T, baseDir string, component cdx.Component) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()
	store, err := oci.New(layout.ComponentLayer(baseDir, component.PackageURL))
	if err != nil {
		t.Fatal(err)
	}
	config, err := oras.PushBytes(ctx, store, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux"}`))
	if err != nil {
		t.Fatal(err)
	}
	layer, err := oras.PushBytes(ctx, store, ocispec.MediaTypeImageLayerGzip, []byte("the image's one layer"))
	if err != nil {
		t.Fatal(err)
	}
	packOpts := oras.PackManifestOptions{
		ConfigDescriptor:    &config,
		Layers:              []ocispec.Descriptor{layer},
		ManifestAnnotations: map[string]string{ocispec.AnnotationCreated: "2026-01-01T00:00:00Z"},
	}
	manifest, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "", packOpts)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, manifest, "1.0"); err != nil {
		t.Fatal(err)
	}
	return manifest
}

// fetchPackage returns the package tag names in store.
func fetchPackage(t *testing.T, store *oci.Store, tag string) (ocispec.Descriptor, *transfer.Package) {
	t.Helper()
	ctx := context.Background()
	desc, err := store.Resolve(ctx, tag)
	if err != nil {
		t.Fatalf("resolve %s: %v", tag, err)
	}
	pkg, err := transfer.FetchPackage(ctx, store, desc)
	if err != nil {
		t.Fatalf("FetchPackage: %v", err)
	}
	return desc, pkg
}

// componentEntry returns the index entry of the component purl names in
// pkg.
func componentEntry(t *testing.T, pkg *transfer.Package, purl string) ocispec.Descriptor {
	t.Helper()
	index := slices.IndexFunc(pkg.Components, func(d ocispec.Descriptor) bool { return d.Annotations[transfer.AnnotationPurl] == purl })
	if index < 0 {
		t.Fatalf("package index has no entry for %s", purl)
	}
	return pkg.Components[index]
}

// componentManifestOf returns the manifest of the component purl names in
// the package tag names in store.
func componentManifestOf(t *testing.T, store *oci.Store, tag, purl string) ocispec.Manifest {
	t.Helper()
	_, pkg := fetchPackage(t, store, tag)
	entry := componentEntry(t, pkg, purl)
	return fetchManifest(t, store, entry)
}

// filesOf returns the files map entry of the component purl names in pkg,
// or nil if it has none.
func filesOf(t *testing.T, store *oci.Store, pkg *transfer.Package, purl string) *transfer.ComponentFiles {
	t.Helper()
	files, err := transfer.FetchFiles(context.Background(), store, pkg)
	if err != nil {
		t.Fatalf("FetchFiles: %v", err)
	}
	component, ok := files.Component(purl)
	if !ok {
		return nil
	}
	return &component
}

func filePaths(files []transfer.FileBlob) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}

// TestPushPackagesAnIndex covers the package's layout: an index of the
// SBOM's manifest, first, and each component's, annotated with its purl
// on the index; a component without a format of its own in bomify's, and
// a model as ModelPack, both restored through the files map.
func TestPushPackagesAnIndex(t *testing.T) {
	weightSize(t, 16)
	baseDir := t.TempDir()
	dataFiles := map[string]string{"a.txt": "a"}
	modelFiles := map[string]string{
		"config.json":         "{}",
		"weights/model.bin":   strings.Repeat("0123456789", 10),
		"tokenizer/vocab.txt": "vocab",
	}
	writeLayer(t, baseDir, dataComponent, dataFiles)
	writeLayer(t, baseDir, modelComponent, modelFiles)
	// A component the SBOM lists twice is in the index once.
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent, modelComponent, dataComponent})
	store := newStore(t)
	ctx := context.Background()

	tagPackage(t, baseDir, "pkg", sbomHash)
	result, err := Push(ctx, store, "pkg", baseDir, transfer.Options{Concurrency: 3})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	desc, pkg := fetchPackage(t, store, "pkg")
	if desc.Digest != result.Manifest.Digest || desc.MediaType != ocispec.MediaTypeImageIndex {
		t.Fatalf("tag points at %s, a %s; want the pushed index %s", desc.Digest, desc.MediaType, result.Manifest.Digest)
	}
	if got := pkg.Index.Annotations[ocispec.AnnotationCreated]; got != "1970-01-01T00:00:00Z" {
		t.Errorf("index created = %q, want the epoch for an SBOM without a timestamp", got)
	}
	if first := pkg.Index.Manifests[0]; first.Digest != pkg.SBOM.Digest {
		t.Errorf("index's first entry is %s, want the SBOM manifest %s", first.Digest, pkg.SBOM.Digest)
	}
	var purls []string
	for _, entry := range pkg.Components {
		purls = append(purls, entry.Annotations[transfer.AnnotationPurl])
	}
	if want := []string{dataComponent.PackageURL, modelComponent.PackageURL}; !slices.Equal(purls, want) {
		t.Errorf("index components = %v, want %v, once each, in the SBOM's order", purls, want)
	}

	sbomData, err := os.ReadFile(layout.Manifest(baseDir, sbomHash))
	if err != nil {
		t.Fatal(err)
	}
	if config := pkg.SBOMManifest.Config; config.Digest != digest.FromBytes(sbomData) {
		t.Errorf("SBOM manifest's config is %s, want the SBOM", config.Digest)
	}
	if layers := pkg.SBOMManifest.Layers; len(layers) != 1 || layers[0].MediaType != transfer.FilesMediaType {
		t.Errorf("SBOM manifest's layers = %v, want just the files map", layers)
	}

	data := componentManifestOf(t, store, "pkg", dataComponent.PackageURL)
	if data.ArtifactType != transfer.ComponentArtifactType || len(data.Layers) != 1 || data.Layers[0].MediaType != transfer.FileMediaType || data.Layers[0].Annotations[ocispec.AnnotationTitle] != "a.txt" {
		t.Errorf("data component's manifest = %+v, want bomify's own format, a layer per file", data)
	}
	if files := filesOf(t, store, pkg, dataComponent.PackageURL); files == nil || !slices.Equal(filePaths(files.Files), []string{"a.txt"}) {
		t.Errorf("files map = %+v, want the data component's file", files)
	}

	model := componentManifestOf(t, store, "pkg", modelComponent.PackageURL)
	if entry := componentEntry(t, pkg, modelComponent.PackageURL); model.ArtifactType != modelspec.ArtifactTypeModelManifest || entry.ArtifactType != modelspec.ArtifactTypeModelManifest {
		t.Errorf("model's manifest is of artifact type %q, %q on the index; want ModelPack's", model.ArtifactType, entry.ArtifactType)
	}
	var config modelspec.Model
	configData, err := content.FetchAll(ctx, store, model.Config)
	if err != nil || model.Config.MediaType != modelspec.MediaTypeModelConfig || json.Unmarshal(configData, &config) != nil {
		t.Fatalf("model config = %s, %v; want a ModelPack config", configData, err)
	}
	var layerPaths []string
	for index, layer := range model.Layers {
		path := layer.Annotations[modelspec.AnnotationFilepath]
		layerPaths = append(layerPaths, path)
		wantType := modelspec.MediaTypeModelWeightConfigRaw
		if path == "weights/model.bin" {
			wantType = modelspec.MediaTypeModelWeightRaw
		}
		if layer.MediaType != wantType {
			t.Errorf("%s's layer is a %s, want a %s", path, layer.MediaType, wantType)
		}
		if layer.Digest != digest.FromString(modelFiles[path]) {
			t.Errorf("%s's layer isn't the file's own bytes", path)
		}
		if index >= len(config.ModelFS.DiffIDs) || config.ModelFS.DiffIDs[index] != layer.Digest {
			t.Errorf("config's diffIDs %v don't name layer %d, %s", config.ModelFS.DiffIDs, index, layer.Digest)
		}
	}
	wantPaths := []string{"config.json", "tokenizer/vocab.txt", "weights/model.bin"}
	if !slices.Equal(layerPaths, wantPaths) {
		t.Errorf("model layers = %v, want a layer per file, by path, %v", layerPaths, wantPaths)
	}
	if files := filesOf(t, store, pkg, modelComponent.PackageURL); files == nil || !slices.Equal(filePaths(files.Files), wantPaths) {
		t.Errorf("files map = %+v, want the model's files %v", files, wantPaths)
	}

	pulledDir := t.TempDir()
	pulled, err := pull.Pull(ctx, store, "pkg", pulledDir, transfer.Options{Concurrency: 3})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(pulled.Components) != 2 {
		t.Errorf("pulled %d components, want 2", len(pulled.Components))
	}
	for component, want := range map[cdx.Component]map[string]string{dataComponent: dataFiles, modelComponent: modelFiles} {
		if got := readDir(t, layout.ComponentLayer(pulledDir, component.PackageURL)); !mapsEqual(got, want) {
			t.Errorf("pulled %s = %v, want %v", component.Name, got, want)
		}
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}

// TestPushPacksWithThePacker covers components their plugins pack: each
// is in the index as packed, with the same digest, and pull restores its
// directory as it was, from the artifact's blobs and, for the files the
// artifact has no place for, the SBOM manifest's.
func TestPushPacksWithThePacker(t *testing.T) {
	baseDir := t.TempDir()
	image := writeImageLayout(t, baseDir, imageComponent)
	writeLayer(t, baseDir, chartComponent, map[string]string{"chart.tgz": "a chart archive"})
	writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{imageComponent, chartComponent, dataComponent})
	ctx := context.Background()
	opts := transfer.Options{
		Concurrency: 3,
		Pack:        fakePacker,
	}

	store := newStore(t)
	tagPackage(t, baseDir, "pkg", sbomHash)
	result, err := Push(ctx, store, "pkg", baseDir, opts)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	_, pkg := fetchPackage(t, store, "pkg")

	if entry := componentEntry(t, pkg, imageComponent.PackageURL); entry.Digest != image.Digest {
		t.Errorf("image is %s in the index, want its own digest %s", entry.Digest, image.Digest)
	}
	chart := componentManifestOf(t, store, "pkg", chartComponent.PackageURL)
	if chart.Config.MediaType != chartConfigMediaType || len(chart.Layers) != 1 || chart.Layers[0].Digest != digest.FromString("a chart archive") {
		t.Errorf("chart manifest = %+v, want the packed chart", chart)
	}
	if data := componentManifestOf(t, store, "pkg", dataComponent.PackageURL); data.ArtifactType != transfer.ComponentArtifactType {
		t.Errorf("data component is a %q, want bomify's own format for a kind its packer has none for", data.ArtifactType)
	}

	imageFiles := filesOf(t, store, pkg, imageComponent.PackageURL)
	if imageFiles == nil {
		t.Fatal("files map doesn't lay out the image")
	}
	var extras []string
	var extraDigests []digest.Digest
	for _, file := range imageFiles.Files {
		if !strings.HasPrefix(file.Path, "blobs/") {
			extras = append(extras, file.Path)
			extraDigests = append(extraDigests, file.Digest)
		}
	}
	if want := []string{ocispec.ImageIndexFile, ocispec.ImageLayoutFile}; !slices.Equal(extras, want) {
		t.Errorf("image's files beside its blobs = %v, want %v", extras, want)
	}
	// The SBOM manifest carries those, so the package holds them.
	var carried []digest.Digest
	for _, layer := range pkg.SBOMManifest.Layers[1:] {
		if layer.MediaType != transfer.FileMediaType || layer.Annotations[transfer.AnnotationPurl] != imageComponent.PackageURL {
			t.Errorf("SBOM manifest layer %+v isn't one of the image's files", layer)
		}
		carried = append(carried, layer.Digest)
	}
	if !slices.Equal(carried, extraDigests) {
		t.Errorf("SBOM manifest carries %v, want the image's %v, %v", carried, extras, extraDigests)
	}
	if chartFiles := filesOf(t, store, pkg, chartComponent.PackageURL); chartFiles == nil || !slices.Equal(filePaths(chartFiles.Files), []string{"chart.tgz"}) {
		t.Errorf("files map = %+v, want the chart's archive alone: its config and manifest aren't its files", chartFiles)
	}

	pulledDir := t.TempDir()
	if _, err := pull.Pull(ctx, store, "pkg", pulledDir, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	for _, component := range []cdx.Component{imageComponent, chartComponent, dataComponent} {
		want := readDir(t, layout.ComponentLayer(baseDir, component.PackageURL))
		if got := readDir(t, layout.ComponentLayer(pulledDir, component.PackageURL)); !mapsEqual(got, want) {
			t.Errorf("pulled %s = %v, want %v", component.Name, got, want)
		}
	}

	// The pulled package packs and pushes the same again.
	pulledHash, err := os.ReadDir(filepath.Join(pulledDir, "manifests"))
	if err != nil || len(pulledHash) == 0 {
		t.Fatalf("pulled no SBOM record: %v", err)
	}
	tagPackage(t, pulledDir, "pkg", sbomHash)
	again, err := Push(ctx, newStore(t), "pkg", pulledDir, opts)
	if err != nil {
		t.Fatalf("Push of the pulled package: %v", err)
	}
	if again.ManifestDigest != result.ManifestDigest {
		t.Errorf("pushing the pulled package gave %s, want the original %s", again.ManifestDigest, result.ManifestDigest)
	}
}

// TestPackageCopiesWithOras covers what the index is for: a tool that
// knows nothing of bomify copies the whole package, and bomify pulls the
// copy.
func TestPackageCopiesWithOras(t *testing.T) {
	baseDir := t.TempDir()
	writeImageLayout(t, baseDir, imageComponent)
	writeLayer(t, baseDir, chartComponent, map[string]string{"chart.tgz": "a chart archive"})
	writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	writeLayer(t, baseDir, modelComponent, map[string]string{"config.json": "{}"})
	components := []cdx.Component{imageComponent, chartComponent, dataComponent, modelComponent}
	sbomHash := recordSBOM(t, baseDir, components)
	ctx := context.Background()

	store := newStore(t)
	tagPackage(t, baseDir, "pkg", sbomHash)
	if _, err := Push(ctx, store, "pkg", baseDir, transfer.Options{Concurrency: 3, Pack: fakePacker}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	copied := newStore(t)
	if _, err := oras.Copy(ctx, store, "pkg", copied, "pkg", oras.DefaultCopyOptions); err != nil {
		t.Fatalf("oras.Copy: %v", err)
	}

	pulledDir := t.TempDir()
	if _, err := pull.Pull(ctx, copied, "pkg", pulledDir, transfer.Options{Concurrency: 3}); err != nil {
		t.Fatalf("Pull of the copy: %v", err)
	}
	for _, component := range components {
		want := readDir(t, layout.ComponentLayer(baseDir, component.PackageURL))
		if got := readDir(t, layout.ComponentLayer(pulledDir, component.PackageURL)); !mapsEqual(got, want) {
			t.Errorf("pulled %s from the copy = %v, want %v", component.Name, got, want)
		}
	}
}

// TestPushRefusesBadPacks covers checking what a packer, a plugin, says
// before pushing anything.
func TestPushRefusesBadPacks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	blobAt := func(path, mediaType string, size int64) pluginlib.PackedBlob {
		blob := pluginlib.PackedBlob{
			MediaType: mediaType,
			Digest:    digest.FromString("{}").String(),
			Size:      size,
			Path:      path,
		}
		return blob
	}
	for name, tc := range map[string]struct {
		pack func(dir string) pluginlib.PackResult
		want string
	}{
		"a blob outside the component": {
			pack: func(string) pluginlib.PackResult {
				manifest := blobAt(outside, ocispec.MediaTypeImageManifest, 2)
				return pluginlib.PackResult{Manifest: &manifest}
			},
			want: "outside",
		},
		"blobs without a manifest": {
			pack: func(dir string) pluginlib.PackResult {
				return pluginlib.PackResult{Blobs: []pluginlib.PackedBlob{blobAt(filepath.Join(dir, "a.json"), "application/json", 2)}}
			},
			want: "no manifest",
		},
		"a manifest that isn't one": {
			pack: func(dir string) pluginlib.PackResult {
				manifest := blobAt(filepath.Join(dir, "a.json"), "application/json", 2)
				return pluginlib.PackResult{Manifest: &manifest}
			},
			want: "not a manifest",
		},
		"a blob of the wrong size": {
			pack: func(dir string) pluginlib.PackResult {
				manifest := blobAt(filepath.Join(dir, "a.json"), ocispec.MediaTypeImageManifest, 3)
				return pluginlib.PackResult{Manifest: &manifest}
			},
			want: "isn't a file of 3 bytes",
		},
		"inline data that isn't the blob": {
			pack: func(string) pluginlib.PackResult {
				manifest := pluginlib.InlineBlob(ocispec.MediaTypeImageManifest, []byte("{}"))
				manifest.Data = []byte("[]")
				return pluginlib.PackResult{Manifest: &manifest}
			},
			want: "inline data isn't the blob",
		},
		"too much inline data": {
			pack: func(string) pluginlib.PackResult {
				data := make([]byte, pluginlib.MaxInlineBlobSize+1)
				manifest := pluginlib.InlineBlob(ocispec.MediaTypeImageManifest, data)
				return pluginlib.PackResult{Manifest: &manifest}
			},
			want: "more than the",
		},
		"a path and inline data": {
			pack: func(dir string) pluginlib.PackResult {
				manifest := blobAt(filepath.Join(dir, "a.json"), ocispec.MediaTypeImageManifest, 2)
				manifest.Data = []byte("{}")
				return pluginlib.PackResult{Manifest: &manifest}
			},
			want: "not both or neither",
		},
		"neither a path nor inline data": {
			pack: func(string) pluginlib.PackResult {
				manifest := blobAt("", ocispec.MediaTypeImageManifest, 2)
				return pluginlib.PackResult{Manifest: &manifest}
			},
			want: "not both or neither",
		},
	} {
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			writeLayer(t, baseDir, dataComponent, map[string]string{"a.json": "{}"})
			sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent})
			packer := func(_ context.Context, _ cdx.Component, dir string) (*pluginlib.PackResult, error) {
				result := tc.pack(dir)
				return &result, nil
			}
			store := newStore(t)
			tagPackage(t, baseDir, "pkg", sbomHash)
			_, err := Push(context.Background(), store, "pkg", baseDir, transfer.Options{Pack: packer})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Push = %v, want an error containing %q", err, tc.want)
			}
			if _, err := store.Resolve(context.Background(), "pkg"); err == nil {
				t.Error("Push tagged the package despite the error")
			}
		})
	}

	t.Run("a packer's error", func(t *testing.T) {
		baseDir := t.TempDir()
		writeLayer(t, baseDir, dataComponent, map[string]string{"a.json": "{}"})
		sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent})
		packer := func(context.Context, cdx.Component, string) (*pluginlib.PackResult, error) {
			return nil, errors.New("plugin not installed")
		}
		tagPackage(t, baseDir, "pkg", sbomHash)
		if _, err := Push(context.Background(), newStore(t), "pkg", baseDir, transfer.Options{Pack: packer}); err == nil || !strings.Contains(err.Error(), "plugin not installed") {
			t.Errorf("Push = %v, want the packer's error", err)
		}
	})

	t.Run("a symlink beside the artifact", func(t *testing.T) {
		baseDir := t.TempDir()
		writeImageLayout(t, baseDir, imageComponent)
		dir := layout.ComponentLayer(baseDir, imageComponent.PackageURL)
		if err := os.Symlink(ocispec.ImageIndexFile, filepath.Join(dir, "link.json")); err != nil {
			t.Skipf("can't create symlinks here: %v", err)
		}
		sbomHash := recordSBOM(t, baseDir, []cdx.Component{imageComponent})
		tagPackage(t, baseDir, "pkg", sbomHash)
		_, err := Push(context.Background(), newStore(t), "pkg", baseDir, transfer.Options{Pack: fakePacker})
		if err == nil || !strings.Contains(err.Error(), "link.json isn't a regular file") {
			t.Errorf("Push = %v, want the symlink refused", err)
		}
	})
}

// craftedComponent is a component manifest for craftIndex, and the purl
// its index entry names.
type craftedComponent struct {
	purl     string
	manifest ocispec.Descriptor
}

// craftIndex tags as "crafted", in store, a package index of an SBOM
// describing dataComponent, files as its files map, and components, as a
// hostile registry might serve one. mutate, if non-nil, changes the index
// before it's pushed.
func craftIndex(t *testing.T, store *oci.Store, files transfer.Files, components []craftedComponent, mutate func(*ocispec.Index)) {
	t.Helper()
	ctx := context.Background()
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"data","name":"data","version":"1.0","purl":"` + dataComponent.PackageURL + `"}]}`)
	config, err := transfer.PushBytes(ctx, store, sbom, "application/vnd.cyclonedx+json", "sbom", nil)
	if err != nil {
		t.Fatal(err)
	}
	filesData, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	filesDesc, err := transfer.PushBytes(ctx, store, filesData, transfer.FilesMediaType, "files", nil)
	if err != nil {
		t.Fatal(err)
	}
	sbomManifest, err := pushManifest(ctx, store, transfer.SBOMArtifactType, config, []ocispec.Descriptor{filesDesc}, nil)
	if err != nil {
		t.Fatal(err)
	}

	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: transfer.ArtifactType,
		Manifests:    []ocispec.Descriptor{sbomManifest},
	}
	for _, component := range components {
		entry := component.manifest
		entry.Annotations = map[string]string{transfer.AnnotationPurl: component.purl}
		index.Manifests = append(index.Manifests, entry)
	}
	if mutate != nil {
		mutate(&index)
	}
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := transfer.PushBytes(ctx, store, data, ocispec.MediaTypeImageIndex, "index", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, desc, "crafted"); err != nil {
		t.Fatal(err)
	}
}

// craftComponent pushes into store a manifest of artifactType with one
// layer holding content, as a component's, returning it and the layer.
func craftComponent(t *testing.T, store *oci.Store, artifactType, content string) (ocispec.Descriptor, ocispec.Descriptor) {
	t.Helper()
	ctx := context.Background()
	layer, err := transfer.PushBytes(ctx, store, []byte(content), "application/octet-stream", "layer", nil)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pushEmptyConfig(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := pushManifest(ctx, store, artifactType, config, []ocispec.Descriptor{layer}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, layer
}

// TestPullRejectsMalformedPackages covers what pull refuses of a package's
// index and files map, before writing any component.
func TestPullRejectsMalformedPackages(t *testing.T) {
	fileOf := func(path string, mode transfer.FileMode, layer ocispec.Descriptor) transfer.FileBlob {
		blob := transfer.FileBlob{
			Path:      path,
			Mode:      mode,
			MediaType: layer.MediaType,
			Digest:    layer.Digest,
			Size:      layer.Size,
		}
		return blob
	}
	filesOfData := func(files ...transfer.FileBlob) transfer.Files {
		component := transfer.ComponentFiles{
			Purl:  dataComponent.PackageURL,
			Files: files,
		}
		return transfer.Files{Components: []transfer.ComponentFiles{component}}
	}
	for name, tc := range map[string]struct {
		// craft crafts the package in store.
		craft func(t *testing.T, store *oci.Store)
		want  string
	}{
		"a manifest, not an index": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, _ := craftComponent(t, store, transfer.ComponentArtifactType, "evil")
				if err := store.Tag(context.Background(), manifest, "crafted"); err != nil {
					t.Fatal(err)
				}
			},
			want: "isn't a bomify package: it's a",
		},
		"an index of another artifact type": {
			craft: func(t *testing.T, store *oci.Store) {
				craftIndex(t, store, transfer.Files{}, nil, func(index *ocispec.Index) { index.ArtifactType = "application/vnd.example" })
			},
			want: "isn't a bomify package",
		},
		"no SBOM manifest": {
			craft: func(t *testing.T, store *oci.Store) {
				craftIndex(t, store, transfer.Files{}, nil, func(index *ocispec.Index) { index.Manifests = index.Manifests[1:] })
			},
			want: "no SBOM manifest",
		},
		"two SBOM manifests": {
			craft: func(t *testing.T, store *oci.Store) {
				craftIndex(t, store, transfer.Files{}, nil, func(index *ocispec.Index) { index.Manifests = append(index.Manifests, index.Manifests[0]) })
			},
			want: "more than one SBOM manifest",
		},
		"a file outside its component": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, layer := craftComponent(t, store, "application/vnd.example", "evil")
				files := filesOfData(fileOf("../evil", 0o644, layer))
				craftIndex(t, store, files, []craftedComponent{{dataComponent.PackageURL, manifest}}, nil)
			},
			want: "outside its component",
		},
		"a file with an invalid mode": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, layer := craftComponent(t, store, "application/vnd.example", "evil")
				files := filesOfData(fileOf("evil", 0o4755, layer))
				craftIndex(t, store, files, []craftedComponent{{dataComponent.PackageURL, manifest}}, nil)
			},
			want: "invalid file mode",
		},
		"a file named twice": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, layer := craftComponent(t, store, "application/vnd.example", "evil")
				files := filesOfData(fileOf("evil", 0o644, layer), fileOf("evil", 0o644, layer))
				craftIndex(t, store, files, []craftedComponent{{dataComponent.PackageURL, manifest}}, nil)
			},
			want: "more than once",
		},
		"a file of a digest that isn't sha256": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, layer := craftComponent(t, store, "application/vnd.example", "evil")
				file := fileOf("evil", 0o644, layer)
				file.Digest = digest.Digest("md5:" + strings.Repeat("0", 32))
				craftIndex(t, store, filesOfData(file), []craftedComponent{{dataComponent.PackageURL, manifest}}, nil)
			},
			want: "isn't sha256",
		},
		"a file whose blob isn't what it says": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, layer := craftComponent(t, store, "application/vnd.example", "evil")
				file := fileOf("evil", 0o644, layer)
				file.Digest = digest.FromString("something else")
				craftIndex(t, store, filesOfData(file), []craftedComponent{{dataComponent.PackageURL, manifest}}, nil)
			},
			want: "not found",
		},
		"a component the files map doesn't lay out": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, _ := craftComponent(t, store, "application/vnd.example", "evil")
				craftIndex(t, store, transfer.Files{}, []craftedComponent{{dataComponent.PackageURL, manifest}}, nil)
			},
			want: "files map doesn't lay out",
		},
		"a component named twice": {
			craft: func(t *testing.T, store *oci.Store) {
				manifest, layer := craftComponent(t, store, "application/vnd.example", "evil")
				files := filesOfData(fileOf("evil", 0o644, layer))
				twice := []craftedComponent{{dataComponent.PackageURL, manifest}, {dataComponent.PackageURL, manifest}}
				craftIndex(t, store, files, twice, nil)
			},
			want: "twice",
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := newStore(t)
			tc.craft(t, store)
			pulledDir := t.TempDir()

			_, err := pull.Pull(context.Background(), store, "crafted", pulledDir, transfer.Options{Concurrency: 1})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Pull = %v, want an error containing %q", err, tc.want)
			}
			if escaped := findFile(t, filepath.Dir(pulledDir), "evil"); escaped != "" {
				t.Errorf("a file was written to %s", escaped)
			}
			if _, statErr := os.Stat(layout.ComponentLayer(pulledDir, dataComponent.PackageURL)); !os.IsNotExist(statErr) {
				t.Errorf("component directory restored despite the error: %v", statErr)
			}
		})
	}
}

// TestPullComponentsKeeps covers restoring part of a package: only the
// components keep accepts, but the whole SBOM.
func TestPullComponentsKeeps(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	writeLayer(t, baseDir, modelComponent, map[string]string{"config.json": "{}"})
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent, modelComponent})
	store := newStore(t)
	ctx := context.Background()
	tagPackage(t, baseDir, "pkg", sbomHash)
	if _, err := Push(ctx, store, "pkg", baseDir, transfer.Options{}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	pulledDir := t.TempDir()
	keep := func(purl string) bool { return purl == modelComponent.PackageURL }
	result, err := pull.PullComponents(ctx, store, "pkg", pulledDir, transfer.Options{}, keep)
	if err != nil {
		t.Fatalf("PullComponents: %v", err)
	}
	if len(result.Components) != 1 || result.Components[0].Purl != modelComponent.PackageURL {
		t.Errorf("restored %+v, want just the model", result.Components)
	}
	if _, err := os.Stat(layout.ComponentLayer(pulledDir, dataComponent.PackageURL)); !os.IsNotExist(err) {
		t.Errorf("restored the data component keep refused: %v", err)
	}
	if result.SBOMHash != sbomHash {
		t.Errorf("SBOM hash = %s, want %s", result.SBOMHash, sbomHash)
	}
	if _, err := os.Stat(layout.Manifest(pulledDir, sbomHash)); err != nil {
		t.Errorf("SBOM not restored: %v", err)
	}
}
