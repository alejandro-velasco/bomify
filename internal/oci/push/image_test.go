package push

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// writeImage writes an image with one layer of layerContent into
// component's directory under baseDir, as an OCI image layout of it, as
// bomify-plugin-oci stores one, returning its manifest's descriptor and
// bytes.
func writeImage(t *testing.T, baseDir string, component cdx.Component, layerContent string) (ocispec.Descriptor, []byte) {
	t.Helper()
	ctx := context.Background()
	store, err := oci.New(layout.ComponentLayer(baseDir, component.PackageURL))
	if err != nil {
		t.Fatal(err)
	}
	config, err := oras.PushBytes(ctx, store, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	layer, err := oras.PushBytes(ctx, store, ocispec.MediaTypeImageLayer, []byte(layerContent))
	if err != nil {
		t.Fatal(err)
	}
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    config,
		Layers:    []ocispec.Descriptor{layer},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := oras.PushBytes(ctx, store, ocispec.MediaTypeImageManifest, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, desc, "stored"); err != nil {
		t.Fatal(err)
	}
	return desc, data
}

func TestPushPublishesAnImageAsItIs(t *testing.T) {
	image := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "nginx", Version: "1.27", PackageURL: "pkg:OCI/nginx@1.27?repository_url=docker.io/library/nginx"}
	var stored ocispec.Descriptor
	var storedManifest []byte
	write := func(baseDir string) { stored, storedManifest = writeImage(t, baseDir, image, "layer") }
	reg := newRegistry(t)

	result, err := pushBuilt(t, reg, transfer.Options{Concurrency: 2}, []cdx.Component{image}, write)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	want := "registry.example.com/packages/app/oci/nginx:1.27"
	if len(result.Components) != 1 || result.Components[0].Reference != want || result.Components[0].Digest != stored.Digest.String() {
		t.Fatalf("Components = %+v, want %s at the image's own digest %s", result.Components, want, stored.Digest)
	}
	store := reg.store("registry.example.com/packages/app/oci/nginx")
	_, published, err := oras.FetchBytes(context.Background(), store, "1.27", oras.DefaultFetchBytesOptions)
	if err != nil || !bytes.Equal(published, storedManifest) {
		t.Errorf("published manifest = %s, %v; want the stored one, unchanged", published, err)
	}
	// Everything the image refers to was copied.
	if _, err := oras.Copy(context.Background(), store, "1.27", newStore(t), "1.27", oras.DefaultCopyOptions); err != nil {
		t.Errorf("copy the published image: %v", err)
	}
}

func TestPushPublishesAPinnedImageByDigest(t *testing.T) {
	// An image's digest depends only on its content: learn it from a
	// throwaway layout, to pin the purl to it.
	stored, _ := writeImage(t, t.TempDir(), cdx.Component{PackageURL: "pkg:oci/probe"}, "pinned")
	image := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "nginx", Version: stored.Digest.String(), PackageURL: "pkg:oci/nginx@" + stored.Digest.String()}
	write := func(baseDir string) { writeImage(t, baseDir, image, "pinned") }
	reg := newRegistry(t)

	result, err := pushBuilt(t, reg, transfer.Options{}, []cdx.Component{image}, write)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	want := "registry.example.com/packages/app/oci/nginx@" + stored.Digest.String()
	if len(result.Components) != 1 || result.Components[0].Reference != want {
		t.Fatalf("Components = %+v, want %s", result.Components, want)
	}
	store := reg.store("registry.example.com/packages/app/oci/nginx")
	tags, err := listTags(store)
	if err != nil || len(tags) != 0 {
		t.Errorf("tags = %v, %v; want none", tags, err)
	}
	if exists, err := store.Exists(context.Background(), stored); err != nil || !exists {
		t.Errorf("the image isn't there by digest: %v", err)
	}
}

func TestPushTagsAPinnedImageWithItsTagQualifier(t *testing.T) {
	stored, _ := writeImage(t, t.TempDir(), cdx.Component{PackageURL: "pkg:oci/probe"}, "tagged")
	image := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "nginx", Version: stored.Digest.String(), PackageURL: "pkg:oci/nginx@" + stored.Digest.String() + "?tag=1.27"}
	write := func(baseDir string) { writeImage(t, baseDir, image, "tagged") }
	reg := newRegistry(t)

	result, err := pushBuilt(t, reg, transfer.Options{}, []cdx.Component{image}, write)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if want := "registry.example.com/packages/app/oci/nginx:1.27"; len(result.Components) != 1 || result.Components[0].Reference != want {
		t.Fatalf("Components = %+v, want %s", result.Components, want)
	}
}

func TestPushPublishesImagePlatformsAsAnIndex(t *testing.T) {
	amd64 := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "app", Version: "1.0", PackageURL: "pkg:oci/app@1.0?arch=amd64&os=linux"}
	arm64 := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "app", Version: "1.0", PackageURL: "pkg:oci/app@1.0?arch=arm64&os=linux"}
	var images []ocispec.Descriptor
	write := func(baseDir string) {
		first, _ := writeImage(t, baseDir, amd64, "amd64")
		second, _ := writeImage(t, baseDir, arm64, "arm64")
		images = []ocispec.Descriptor{first, second}
	}
	reg := newRegistry(t)

	if _, err := pushBuilt(t, reg, transfer.Options{}, []cdx.Component{amd64, arm64}, write); err != nil {
		t.Fatalf("Push: %v", err)
	}
	var index ocispec.Index
	fetchJSON(t, reg.store("registry.example.com/packages/app/oci/app"), "1.0", &index)
	if len(index.Manifests) != 2 {
		t.Fatalf("index = %+v, want both images", index)
	}
	for position, manifest := range index.Manifests {
		if manifest.Digest != images[position].Digest || manifest.Platform == nil || manifest.Platform.OS != "linux" {
			t.Errorf("index entry %d = %+v, want image %s for linux", position, manifest, images[position].Digest)
		}
	}
}

// listTags lists store's tags.
func listTags(store *oci.Store) ([]string, error) {
	var tags []string
	err := store.Tags(context.Background(), "", func(page []string) error {
		tags = append(tags, page...)
		return nil
	})
	return tags, err
}
