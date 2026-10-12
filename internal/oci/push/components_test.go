package push

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

const packageRef = "registry.example.com/packages/app:1.0"

func TestComponentSiteOf(t *testing.T) {
	tests := []struct {
		purl, want string
	}{
		{"pkg:huggingface/microsoft/Phi-4@187ef0342fff0eb3333be9f00389385e95ef0b61", "registry.example.com/packages/app/huggingface/microsoft/phi-4:187ef0342fff0eb3333be9f00389385e95ef0b61"},
		{"pkg:generic/tool@1.0?download_url=https://example.com/tool", "registry.example.com/packages/app/generic/tool:1.0"},
		{"pkg:npm/%40angular/core@17.0.0", "registry.example.com/packages/app/npm/angular/core:17.0.0"},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "registry.example.com/packages/app/golang/github.com/foo/bar:v1.2.3"},
		{"pkg:generic/tool@1.0.0+build.5", "registry.example.com/packages/app/generic/tool:1.0.0_build.5"},
		{"pkg:generic/tool", "registry.example.com/packages/app/generic/tool:latest"},
		{"pkg:generic/My__Odd..Name-@1", "registry.example.com/packages/app/generic/my__odd-name:1"},
	}
	for _, test := range tests {
		site, err := componentSiteOf("registry.example.com/packages/app", test.purl)
		if err != nil {
			t.Errorf("componentSiteOf(%s): %v", test.purl, err)
			continue
		}
		if got := site.reference(); got != test.want {
			t.Errorf("componentSiteOf(%s) = %s, want %s", test.purl, got, test.want)
		}
	}
}

func TestComponentSiteOfPlatform(t *testing.T) {
	site, err := componentSiteOf("r.example.com/app", "pkg:bomify-plugin/oci@1.0?os=linux&arch=arm64&download_url=x")
	if err != nil {
		t.Fatal(err)
	}
	if site.os != "linux" || site.arch != "arm64" {
		t.Errorf("platform = %s/%s, want linux/arm64", site.os, site.arch)
	}
	if site.unqualified != "pkg:bomify-plugin/oci@1.0?download_url=x" {
		t.Errorf("unqualified = %s", site.unqualified)
	}
}

func TestComponentSiteOfRefusesWhatCantBeNamed(t *testing.T) {
	for _, purl := range []string{"pkg:generic/%40%40@1", "pkg:generic/tool@1:2", "pkg:generic/tool@" + strings.Repeat("1", 129)} {
		if _, err := componentSiteOf("r.example.com/app", purl); err == nil {
			t.Errorf("componentSiteOf(%s) succeeded, want an error", purl)
		}
	}
}

// registry is a set of OCI stores, one per repository, as a registry
// holds them.
type registry struct {
	t      *testing.T
	mutex  sync.Mutex
	stores map[string]*oci.Store
	// refuse, if set, fails every repository but the package's.
	refuse error
}

func newRegistry(t *testing.T) *registry {
	return &registry{t: t, stores: map[string]*oci.Store{}}
}

func (r *registry) target(repository string) (oras.Target, error) {
	if r.refuse != nil {
		return nil, r.refuse
	}
	return r.store(repository), nil
}

func (r *registry) store(repository string) *oci.Store {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if store, ok := r.stores[repository]; ok {
		return store
	}
	store, err := oci.New(r.t.TempDir())
	if err != nil {
		r.t.Fatal(err)
	}
	r.stores[repository] = store
	return store
}

// pushWithComponents pushes components, with files, as packageRef,
// publishing each at its own repository of reg.
func pushWithComponents(t *testing.T, reg *registry, opts transfer.Options, components []cdx.Component, files []map[string]string) (Result, error) {
	t.Helper()
	baseDir := t.TempDir()
	for index, component := range components {
		writeLayer(t, baseDir, component, files[index])
	}
	sbomHash := recordSBOM(t, baseDir, components)
	opts.ComponentTarget = reg.target
	return Push(context.Background(), reg.store("registry.example.com/packages/app"), packageRef, baseDir, sbomHash, opts)
}

// orasPull pulls tag from store as `oras pull` does, into a new
// directory, returning what it wrote.
func orasPull(t *testing.T, store *oci.Store, tag string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	fileStore, err := file.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fileStore.Close()
	if _, err := oras.Copy(context.Background(), store, tag, fileStore, tag, oras.DefaultCopyOptions); err != nil {
		t.Fatalf("oras pull %s: %v", tag, err)
	}
	return readDir(t, dir)
}

func fetchJSON(t *testing.T, store *oci.Store, ref string, v any) ocispec.Descriptor {
	t.Helper()
	desc, data, err := oras.FetchBytes(context.Background(), store, ref, oras.DefaultFetchBytesOptions)
	if err != nil {
		t.Fatalf("fetch %s: %v", ref, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
	return desc
}

func TestPushPublishesAModelAsModelPack(t *testing.T) {
	layerLimits(t, 16, 1024)
	model := cdx.Component{
		Type:       cdx.ComponentTypeMachineLearningModel,
		Name:       "Phi-4",
		Version:    "187ef0342fff0eb3333be9f00389385e95ef0b61",
		PackageURL: "pkg:huggingface/microsoft/Phi-4@187ef0342fff0eb3333be9f00389385e95ef0b61",
	}
	files := map[string]string{
		"config.json":                    `{"a": 1}`,
		"tokenizer/vocab.txt":            "a b c",
		"model-00001.safetensors":        strings.Repeat("0123456789", 10),
		"nested/model-00002.safetensors": strings.Repeat("abcde", 10),
	}
	reg := newRegistry(t)

	result, err := pushWithComponents(t, reg, transfer.Options{Concurrency: 2}, []cdx.Component{model}, []map[string]string{files})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	repository := "registry.example.com/packages/app/huggingface/microsoft/phi-4"
	want := PublishedComponent{
		Purls:     []string{model.PackageURL},
		Reference: repository + ":" + model.Version,
	}
	if len(result.Components) != 1 || result.Components[0].Reference != want.Reference || !slices.Equal(result.Components[0].Purls, want.Purls) {
		t.Fatalf("Components = %+v, want %+v", result.Components, want)
	}
	store := reg.store(repository)
	if got := orasPull(t, store, model.Version); !maps.Equal(got, files) {
		t.Errorf("oras pull wrote %v, want %v", got, files)
	}

	var manifest ocispec.Manifest
	fetchJSON(t, store, model.Version, &manifest)
	if manifest.ArtifactType != ModelArtifactType || manifest.Config.MediaType != modelConfigMediaType {
		t.Errorf("artifact type %s, config %s, want ModelPack's", manifest.ArtifactType, manifest.Config.MediaType)
	}
	if manifest.Annotations[AnnotationPackageDigest] != result.ManifestDigest || manifest.Annotations[transfer.AnnotationPurl] != model.PackageURL {
		t.Errorf("annotations = %v, want the purl and package digest %s", manifest.Annotations, result.ManifestDigest)
	}
	var mediaTypes []string
	for _, layer := range manifest.Layers {
		mediaTypes = append(mediaTypes, layer.MediaType)
	}
	wantTypes := []string{modelConfigTarMediaType, modelWeightMediaType, modelWeightMediaType}
	if !slices.Equal(mediaTypes, wantTypes) {
		t.Errorf("layer media types = %v, want %v", mediaTypes, wantTypes)
	}

	var config modelConfig
	configData, err := content.FetchAll(context.Background(), store, manifest.Config)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatal(err)
	}
	if config.ModelFS.Type != "layers" || len(config.ModelFS.DiffIDs) != 3 || config.Descriptor.Name != "Phi-4" {
		t.Errorf("config = %+v", config)
	}
	if config.ModelFS.DiffIDs[1] != manifest.Layers[1].Digest || config.ModelFS.DiffIDs[0] != digest.Digest(manifest.Layers[0].Annotations[annotationOrasTarDigest]) {
		t.Errorf("diffIds = %v, want the tar's uncompressed digest and the weights' own", config.ModelFS.DiffIDs)
	}

	// The weights are the package's own blobs.
	var pkg ocispec.Manifest
	fetchJSON(t, reg.store("registry.example.com/packages/app"), packageRef, &pkg)
	for _, layer := range manifest.Layers[1:] {
		if !slices.ContainsFunc(pkg.Layers, func(packaged ocispec.Descriptor) bool { return packaged.Digest == layer.Digest }) {
			t.Errorf("weight %s isn't one of the package's blobs", layer.Annotations[ocispec.AnnotationTitle])
		}
	}
}

func TestPushPublishesFilesAsAnArtifact(t *testing.T) {
	files := map[string]string{"bin/tool": "#!/bin/sh", "README": "hi"}
	component := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?download_url=https://example.com/tool"}
	image := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}
	reg := newRegistry(t)

	result, err := pushWithComponents(t, reg, transfer.Options{}, []cdx.Component{component, image}, []map[string]string{files, {"oci-layout": "{}"}})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(result.Components) != 1 {
		t.Fatalf("Components = %+v, want only the tool's: images aren't published yet", result.Components)
	}
	store := reg.store("registry.example.com/packages/app/generic/tool")
	if got := orasPull(t, store, "1.0"); !maps.Equal(got, files) {
		t.Errorf("oras pull wrote %v, want %v", got, files)
	}
	var manifest ocispec.Manifest
	fetchJSON(t, store, "1.0", &manifest)
	if manifest.ArtifactType != ComponentArtifactType || manifest.Layers[0].MediaType != ComponentTarGzMediaType {
		t.Errorf("artifact type %s, layer %s", manifest.ArtifactType, manifest.Layers[0].MediaType)
	}
}

func TestPushPublishesPlatformsAsAnIndex(t *testing.T) {
	amd64 := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "oci", Version: "1.0", PackageURL: "pkg:bomify-plugin/oci@1.0?os=linux&arch=amd64"}
	arm64 := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "oci", Version: "1.0", PackageURL: "pkg:bomify-plugin/oci@1.0?os=linux&arch=arm64"}
	reg := newRegistry(t)

	result, err := pushWithComponents(t, reg, transfer.Options{}, []cdx.Component{amd64, arm64}, []map[string]string{{"plugin": "amd64"}, {"plugin": "arm64"}})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(result.Components) != 1 || len(result.Components[0].Purls) != 2 {
		t.Fatalf("Components = %+v, want one index of both", result.Components)
	}
	var index ocispec.Index
	fetchJSON(t, reg.store("registry.example.com/packages/app/bomify-plugin/oci"), "1.0", &index)
	var platforms []string
	for _, manifest := range index.Manifests {
		platforms = append(platforms, manifest.Platform.OS+"/"+manifest.Platform.Architecture)
	}
	if !slices.Equal(platforms, []string{"linux/amd64", "linux/arm64"}) {
		t.Errorf("platforms = %v", platforms)
	}
}

func TestPushRefusesTwoComponentsAtOneRepository(t *testing.T) {
	first := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?download_url=https://a.example.com/tool"}
	second := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?download_url=https://b.example.com/tool"}
	reg := newRegistry(t)

	_, err := pushWithComponents(t, reg, transfer.Options{}, []cdx.Component{first, second}, []map[string]string{{"tool": "a"}, {"tool": "b"}})
	if err == nil || !strings.Contains(err.Error(), "would both be published at") {
		t.Fatalf("Push error = %v, want a collision", err)
	}

	// A platform's component and one for no platform aren't one index.
	reg = newRegistry(t)
	linux := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?download_url=https://a.example.com/tool&os=linux"}
	_, err = pushWithComponents(t, reg, transfer.Options{}, []cdx.Component{first, linux}, []map[string]string{{"tool": "a"}, {"tool": "b"}})
	if err == nil || !strings.Contains(err.Error(), "would both be published at") {
		t.Fatalf("Push error = %v, want a collision", err)
	}

	// The same content twice is published once.
	reg = newRegistry(t)
	result, err := pushWithComponents(t, reg, transfer.Options{}, []cdx.Component{first, second}, []map[string]string{{"tool": "a"}, {"tool": "a"}})
	if err != nil || len(result.Components) != 1 {
		t.Fatalf("Push = %+v, %v; want one component published", result.Components, err)
	}
}

func TestPushSignsEachComponentBeforeTagging(t *testing.T) {
	component := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0"}
	var signed []string
	sign := func(_ context.Context, target oras.Target, ref string, manifest ocispec.Descriptor) error {
		signed = append(signed, ref)
		if strings.Contains(ref, "/generic/") {
			if _, err := target.Resolve(context.Background(), "1.0"); err == nil {
				return errors.New("signed after tagging")
			}
		}
		return nil
	}
	reg := newRegistry(t)

	if _, err := pushWithComponents(t, reg, transfer.Options{Sign: sign}, []cdx.Component{component}, []map[string]string{{"tool": "a"}}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	want := []string{packageRef, "registry.example.com/packages/app/generic/tool:1.0"}
	if !slices.Equal(signed, want) {
		t.Errorf("signed %v, want %v", signed, want)
	}
}

func TestPushLeavesThePackageUntaggedWhenARepositoryFails(t *testing.T) {
	component := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0"}
	reg := newRegistry(t)
	pkgStore := reg.store("registry.example.com/packages/app")
	reg.refuse = errors.New("name unknown")

	_, err := pushWithComponents(t, reg, transfer.Options{}, []cdx.Component{component}, []map[string]string{{"tool": "a"}})
	var repositoryErr *ComponentRepositoryError
	if !errors.As(err, &repositoryErr) {
		t.Fatalf("Push error = %v, want a ComponentRepositoryError", err)
	}
	if _, err := pkgStore.Resolve(context.Background(), packageRef); err == nil {
		t.Error("the package was tagged though a component repository failed")
	}
}

func TestPushPublishesComponentsDeterministically(t *testing.T) {
	component := cdx.Component{Type: cdx.ComponentTypeMachineLearningModel, Name: "m", Version: "1", PackageURL: "pkg:generic/m@1"}
	var digests []string
	for range 2 {
		reg := newRegistry(t)
		result, err := pushWithComponents(t, reg, transfer.Options{}, []cdx.Component{component}, []map[string]string{{"config.json": "{}"}})
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, result.Components[0].Digest)
	}
	if digests[0] != digests[1] {
		t.Errorf("digests %v differ between identical pushes", digests)
	}
}
