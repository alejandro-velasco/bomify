package push

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/package-url/packageurl-go"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// packageRepository is the repository the alias tests push packages to,
// and packageRef the package's reference there.
const (
	packageRepository = "registry.example.com/packages/app"
	packageRef        = packageRepository + ":1.0"
)

func TestComponentSiteOf(t *testing.T) {
	tests := []struct {
		purl, want string
	}{
		{"pkg:huggingface/microsoft/Phi-4@187ef0342fff0eb3333be9f00389385e95ef0b61", "huggingface/microsoft/phi-4:187ef0342fff0eb3333be9f00389385e95ef0b61"},
		{"pkg:generic/tool@1.0?download_url=https://example.com/tool", "generic/tool:1.0"},
		{"pkg:npm/%40angular/core@17.0.0", "npm/angular/core:17.0.0"},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang/github.com/foo/bar:v1.2.3"},
		{"pkg:helm/podinfo@6.7.1+build.5?repository_url=https://example.com", "helm/podinfo:6.7.1_build.5"},
		{"pkg:generic/tool", "generic/tool:latest"},
		{"pkg:generic/My__Odd..Name-@1", "generic/my__odd-name:1"},
		{"pkg:oci/nginx@1.27?repository_url=docker.io/library/nginx", "oci/nginx:1.27"},
		{"pkg:oci/nginx@sha256:" + strings.Repeat("a", 64) + "?tag=1.27", "oci/nginx:1.27"},
		{"pkg:oci/nginx@sha256:" + strings.Repeat("a", 64), "oci/nginx@sha256:" + strings.Repeat("a", 64)},
	}
	for _, test := range tests {
		site, err := componentSiteOf(parsePurl(t, test.purl))
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
	site, err := componentSiteOf(parsePurl(t, "pkg:bomify-plugin/oci@1.0?os=linux&arch=arm64&download_url=x"))
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
		if _, err := componentSiteOf(parsePurl(t, purl)); err == nil {
			t.Errorf("componentSiteOf(%s) succeeded, want an error", purl)
		}
	}
}

func parsePurl(t *testing.T, purl string) packageurl.PackageURL {
	t.Helper()
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// registry is a set of OCI stores, one per repository, as a registry
// holds them.
type registry struct {
	t      *testing.T
	mutex  sync.Mutex
	stores map[string]*oci.Store
	// refuse, if set, fails every repository but the package's.
	refuse error
	// cannotMount makes the components' repositories plain stores, which
	// have no mount at all.
	cannotMount bool
	// mounted and uploaded are what each component repository was given
	// by mount and by upload, as "<repository> <media type>".
	mounted, uploaded []string
}

func newRegistry(t *testing.T) *registry {
	return &registry{t: t, stores: map[string]*oci.Store{}}
}

// target is a transfer.Options.ComponentTarget for r.
func (r *registry) target(repository string) (oras.Target, error) {
	if r.refuse != nil {
		return nil, r.refuse
	}
	if r.cannotMount {
		return r.store(repository), nil
	}
	target := mountingStore{
		Store:      r.store(repository),
		reg:        r,
		repository: repository,
	}
	return target, nil
}

func (r *registry) record(list *[]string, entry string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	*list = append(*list, entry)
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

// mountingStore is a component's repository in a registry that can mount a
// blob from another of its repositories.
type mountingStore struct {
	*oci.Store
	reg        *registry
	repository string
}

// Push records an upload of expected.
func (s mountingStore) Push(ctx context.Context, expected ocispec.Descriptor, content io.Reader) error {
	s.reg.record(&s.reg.uploaded, s.repository+" "+expected.MediaType)
	return s.Store.Push(ctx, expected, content)
}

// Mount links desc from fromRepo, a repository of the registry named by
// path, if it holds it; otherwise, like a registry that won't mount, it
// takes the upload getContent starts.
func (s mountingStore) Mount(ctx context.Context, desc ocispec.Descriptor, fromRepo string, getContent func() (io.ReadCloser, error)) error {
	source := s.reg.store("registry.example.com/" + fromRepo)
	held, err := source.Exists(ctx, desc)
	if err != nil {
		return err
	}
	if held {
		blob, err := source.Fetch(ctx, desc)
		if err != nil {
			return err
		}
		defer blob.Close()
		s.reg.record(&s.reg.mounted, s.repository+" "+desc.MediaType)
		return s.Store.Push(ctx, desc, blob)
	}
	content, err := getContent()
	if err != nil {
		return err
	}
	defer content.Close()
	return s.Push(ctx, desc, content)
}

// pushToRegistry pushes components, which write has written the files of
// into the data directory it's given, as packageRef in reg, with opts.
func pushToRegistry(t *testing.T, reg *registry, opts transfer.Options, components []cdx.Component, write func(baseDir string)) (Result, error) {
	t.Helper()
	baseDir := t.TempDir()
	write(baseDir)
	sbomHash := recordSBOM(t, baseDir, components)
	tagPackage(t, baseDir, packageRef, sbomHash)
	return Push(context.Background(), reg.store(packageRepository), packageRef, baseDir, opts)
}

// TestPushTagsComponentsBesideThePackage covers what component repositories
// are for: each component, by name, where its own tools pull it, as the
// very manifest the package's index holds, its blobs mounted from the
// package's repository rather than uploaded again.
func TestPushTagsComponentsBesideThePackage(t *testing.T) {
	reg := newRegistry(t)
	components := []cdx.Component{imageComponent, chartComponent, modelComponent, dataComponent}
	write := func(baseDir string) {
		writeImageLayout(t, baseDir, imageComponent)
		writeLayer(t, baseDir, chartComponent, map[string]string{"chart.tgz": "a chart archive"})
		writeLayer(t, baseDir, modelComponent, map[string]string{"config.json": "{}"})
		writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	}
	opts := transfer.Options{
		Concurrency:     2,
		Pack:            fakePacker,
		ComponentTarget: reg.target,
	}

	result, err := pushToRegistry(t, reg, opts, components, write)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	_, pkg := fetchPackage(t, reg.store(packageRepository), packageRef)
	want := map[string]string{
		imageComponent.PackageURL: "oci/image:1.0",
		chartComponent.PackageURL: "helm/chart:1.0",
		modelComponent.PackageURL: "huggingface/org/model:2db69c1c3e91a05d2c64a3185acfbaf36f744e25",
		dataComponent.PackageURL:  "generic/data:1.0",
	}
	var references []string
	for _, tagged := range result.TaggedComponents {
		references = append(references, tagged.Reference)
	}
	for _, component := range components {
		entry := componentEntry(t, pkg, component.PackageURL)
		relative := want[component.PackageURL]
		if got := entry.Annotations[transfer.AnnotationComponentReference]; got != relative {
			t.Errorf("%s's index entry names %q, want %q", component.Name, got, relative)
		}

		repository, tag, _ := strings.Cut(relative, ":")
		reference := packageRepository + "/" + repository + ":" + tag
		if !slices.Contains(references, reference) {
			t.Errorf("TaggedComponents = %v, want %s among them", references, reference)
		}
		store := reg.store(packageRepository + "/" + repository)
		tagged, err := store.Resolve(context.Background(), tag)
		if err != nil {
			t.Errorf("%s isn't tagged: %v", reference, err)
			continue
		}
		if tagged.Digest != entry.Digest {
			t.Errorf("%s is %s, want the index's manifest %s", reference, tagged.Digest, entry.Digest)
		}
		// Everything the manifest names is there, as its tools pull it.
		successors, err := content.Successors(context.Background(), store, tagged)
		if err != nil {
			t.Fatalf("%s's manifest: %v", reference, err)
		}
		for _, successor := range successors {
			if held, err := store.Exists(context.Background(), successor); err != nil || !held {
				t.Errorf("%s lacks %s it names", reference, successor.Digest)
			}
		}
	}

	// Every blob was mounted; only manifests, which a registry can't mount,
	// were uploaded.
	if len(reg.mounted) == 0 {
		t.Error("nothing was mounted from the package's repository")
	}
	for _, uploaded := range reg.uploaded {
		if !slices.Contains(transfer.ManifestMediaTypes, uploaded[strings.LastIndex(uploaded, " ")+1:]) {
			t.Errorf("uploaded %s, want every blob mounted", uploaded)
		}
	}
}

// TestPushTagsComponentsWhereNothingMounts covers a registry, or a store,
// that can't mount: each blob is uploaded instead.
func TestPushTagsComponentsWhereNothingMounts(t *testing.T) {
	reg := newRegistry(t)
	reg.cannotMount = true
	write := func(baseDir string) {
		writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	}
	opts := transfer.Options{ComponentTarget: reg.target}
	if _, err := pushToRegistry(t, reg, opts, []cdx.Component{dataComponent}, write); err != nil {
		t.Fatalf("Push: %v", err)
	}
	store := reg.store(packageRepository + "/generic/data")
	desc, err := store.Resolve(context.Background(), "1.0")
	if err != nil {
		t.Fatalf("generic/data:1.0 isn't tagged: %v", err)
	}
	manifest := fetchManifest(t, store, desc)
	if held, err := store.Exists(context.Background(), manifest.Layers[0]); err != nil || !held {
		t.Errorf("the component's layer wasn't uploaded: %v", err)
	}
}

// TestPushTagsPlatformsAsAnIndex covers components that differ only by
// platform: tagged together, as an index of each platform's manifest.
func TestPushTagsPlatformsAsAnIndex(t *testing.T) {
	reg := newRegistry(t)
	amd64 := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?arch=amd64&os=linux"}
	arm64 := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?arch=arm64&os=linux"}
	write := func(baseDir string) {
		writeLayer(t, baseDir, amd64, map[string]string{"tool": "amd64"})
		writeLayer(t, baseDir, arm64, map[string]string{"tool": "arm64"})
	}
	opts := transfer.Options{ComponentTarget: reg.target}
	result, err := pushToRegistry(t, reg, opts, []cdx.Component{amd64, arm64}, write)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(result.TaggedComponents) != 1 || len(result.TaggedComponents[0].Purls) != 2 {
		t.Fatalf("TaggedComponents = %+v, want both platforms at one site", result.TaggedComponents)
	}

	store := reg.store(packageRepository + "/generic/tool")
	var index ocispec.Index
	desc, data, err := oras.FetchBytes(context.Background(), store, "1.0", oras.DefaultFetchBytesOptions)
	if err != nil {
		t.Fatalf("generic/tool:1.0 isn't tagged: %v", err)
	}
	if err := json.Unmarshal(data, &index); err != nil || desc.MediaType != ocispec.MediaTypeImageIndex {
		t.Fatalf("generic/tool:1.0 is a %s, %v; want an index", desc.MediaType, err)
	}
	var platforms []string
	for _, manifest := range index.Manifests {
		platforms = append(platforms, manifest.Platform.OS+"/"+manifest.Platform.Architecture)
	}
	if !slices.Equal(platforms, []string{"linux/amd64", "linux/arm64"}) {
		t.Errorf("index platforms = %v, want linux/amd64 and linux/arm64", platforms)
	}
}

// TestPushPlacesTwoComponentsAtOneSite covers components that would be
// tagged alike with different content, and aren't platforms of one: a
// push that tags refuses them before the package is tagged, and one that
// doesn't, such as a save, pushes the package, its index naming a site
// for the first alone.
func TestPushPlacesTwoComponentsAtOneSite(t *testing.T) {
	first := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?download_url=https://a.example.com/tool"}
	second := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0?download_url=https://b.example.com/tool"}
	write := func(baseDir string) {
		writeLayer(t, baseDir, first, map[string]string{"tool": "first"})
		writeLayer(t, baseDir, second, map[string]string{"tool": "second"})
	}

	t.Run("tagging", func(t *testing.T) {
		reg := newRegistry(t)
		opts := transfer.Options{ComponentTarget: reg.target}
		_, err := pushToRegistry(t, reg, opts, []cdx.Component{first, second}, write)
		if !errors.Is(err, ErrComponentRepository) || !strings.Contains(err.Error(), "would both be tagged generic/tool:1.0") {
			t.Fatalf("Push = %v, want the collision refused", err)
		}
		if _, err := reg.store(packageRepository).Resolve(context.Background(), packageRef); err == nil {
			t.Error("the package was tagged despite the collision")
		}
	})

	t.Run("not tagging", func(t *testing.T) {
		reg := newRegistry(t)
		if _, err := pushToRegistry(t, reg, transfer.Options{}, []cdx.Component{first, second}, write); err != nil {
			t.Fatalf("Push: %v", err)
		}
		_, pkg := fetchPackage(t, reg.store(packageRepository), packageRef)
		if got := componentEntry(t, pkg, first.PackageURL).Annotations[transfer.AnnotationComponentReference]; got != "generic/tool:1.0" {
			t.Errorf("first's reference = %q, want generic/tool:1.0", got)
		}
		if got, ok := componentEntry(t, pkg, second.PackageURL).Annotations[transfer.AnnotationComponentReference]; ok {
			t.Errorf("second's reference = %q, want none", got)
		}
	})
}

// TestPushSignsEachTaggedComponent covers signing: each component, where
// it's tagged, as well as the package.
func TestPushSignsEachTaggedComponent(t *testing.T) {
	reg := newRegistry(t)
	write := func(baseDir string) {
		writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	}
	var mutex sync.Mutex
	var signed []string
	sign := func(ctx context.Context, target oras.Target, ref string, desc ocispec.Descriptor) error {
		mutex.Lock()
		defer mutex.Unlock()
		// Not yet tagged when it's signed: a package is tagged by its
		// reference, a component in its repository by its tag.
		tag := ref[strings.LastIndex(ref, ":")+1:]
		for _, name := range []string{ref, tag} {
			if _, err := target.Resolve(ctx, name); err == nil {
				return errors.New(ref + " was tagged before it was signed")
			}
		}
		signed = append(signed, ref)
		return nil
	}
	opts := transfer.Options{
		ComponentTarget: reg.target,
		Sign:            sign,
	}
	if _, err := pushToRegistry(t, reg, opts, []cdx.Component{dataComponent}, write); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if !slices.Contains(signed, packageRepository+"/generic/data:1.0") || !slices.Contains(signed, packageRef) {
		t.Errorf("signed %v, want the package and generic/data:1.0", signed)
	}
}

// TestPushLeavesThePackageUntaggedWhenARepositoryFails covers a registry
// that can't host a component's repository: the push fails, saying so, and
// the package isn't tagged.
func TestPushLeavesThePackageUntaggedWhenARepositoryFails(t *testing.T) {
	reg := newRegistry(t)
	reg.refuse = errors.New("no nested repositories")
	write := func(baseDir string) {
		writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	}
	_, err := pushToRegistry(t, reg, transfer.Options{ComponentTarget: reg.target}, []cdx.Component{dataComponent}, write)
	if !errors.Is(err, ErrComponentRepository) || !strings.Contains(err.Error(), "no nested repositories") {
		t.Fatalf("Push = %v, want an ErrComponentRepository", err)
	}
	if _, err := reg.store(packageRepository).Resolve(context.Background(), packageRef); err == nil {
		t.Error("the package was tagged despite the failure")
	}
}

// TestPushIndexIsTheSameWithOrWithoutTags covers the index naming where
// components are tagged relative to the package: the same digest whether
// they're tagged or not, and so wherever the package is.
func TestPushIndexIsTheSameWithOrWithoutTags(t *testing.T) {
	write := func(baseDir string) {
		writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	}
	tagging := newRegistry(t)
	tagged, err := pushToRegistry(t, tagging, transfer.Options{ComponentTarget: tagging.target}, []cdx.Component{dataComponent}, write)
	if err != nil {
		t.Fatalf("Push, tagging: %v", err)
	}
	untagged, err := pushToRegistry(t, newRegistry(t), transfer.Options{}, []cdx.Component{dataComponent}, write)
	if err != nil {
		t.Fatalf("Push, not tagging: %v", err)
	}
	if tagged.ManifestDigest != untagged.ManifestDigest {
		t.Errorf("index digests %s and %s differ", tagged.ManifestDigest, untagged.ManifestDigest)
	}
	if len(untagged.TaggedComponents) != 0 {
		t.Errorf("TaggedComponents = %+v without a ComponentTarget, want none", untagged.TaggedComponents)
	}
}
