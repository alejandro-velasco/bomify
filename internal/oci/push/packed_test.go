package push

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// layoutPacker packs a component as bomify-plugin-oci packs an image: the
// image of the OCI image layout in its directory, its manifest, config, and
// layers listed as they are.
type layoutPacker struct{}

func (layoutPacker) CanPack(cdx.Component) error { return nil }

func (layoutPacker) Pack(_ context.Context, _ cdx.Component, input, _ string, _ map[string]string) (pluginlib.PackResult, error) {
	packed := func(desc ocispec.Descriptor) pluginlib.PackedBlob {
		blob := pluginlib.PackedBlob{
			MediaType: desc.MediaType,
			Digest:    desc.Digest.String(),
			Size:      desc.Size,
			Path:      filepath.Join(input, ocispec.ImageBlobsDir, desc.Digest.Algorithm().String(), desc.Digest.Encoded()),
		}
		return blob
	}
	var index ocispec.Index
	if err := readJSON(filepath.Join(input, ocispec.ImageIndexFile), &index); err != nil {
		return pluginlib.PackResult{}, err
	}
	image := packed(index.Manifests[0])
	var manifest ocispec.Manifest
	if err := readJSON(image.Path, &manifest); err != nil {
		return pluginlib.PackResult{}, err
	}

	result := pluginlib.PackResult{
		Manifest: &image,
		Blobs:    []pluginlib.PackedBlob{packed(manifest.Config)},
	}
	for _, layer := range manifest.Layers {
		result.Blobs = append(result.Blobs, packed(layer))
	}
	return result, nil
}

// readJSON reads the JSON file at path into v.
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// fakePacker packs every component with pack, after checking it with
// canPack, if set, and records the annotations it was given.
type fakePacker struct {
	canPack     func(cdx.Component) error
	pack        func(input, output string) pluginlib.PackResult
	annotations map[string]string
}

func (p *fakePacker) CanPack(component cdx.Component) error {
	if p.canPack == nil {
		return nil
	}
	return p.canPack(component)
}

func (p *fakePacker) Pack(_ context.Context, _ cdx.Component, input, output string, annotations map[string]string) (pluginlib.PackResult, error) {
	p.annotations = maps.Clone(annotations)
	if p.pack == nil {
		return pluginlib.PackResult{}, nil
	}
	return p.pack(input, output), nil
}

func TestPushChecksComponentsCanBePackedBeforePushingAnything(t *testing.T) {
	component := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0"}
	baseDir := t.TempDir()
	writeLayer(t, baseDir, component, map[string]string{"tool": "a"})
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{component})
	packageDir := t.TempDir()
	store, err := oci.New(packageDir)
	if err != nil {
		t.Fatal(err)
	}
	refusal := errors.New("bomify-plugin-generic isn't installed")
	opts := transfer.Options{
		ComponentTarget: newRegistry(t).target,
		ComponentPacker: &fakePacker{canPack: func(cdx.Component) error { return refusal }},
	}

	_, err = pushTagged(t, context.Background(), store, packageRef, baseDir, sbomHash, opts)
	if !errors.Is(err, refusal) {
		t.Fatalf("Push error = %v, want the packer's refusal", err)
	}
	if blobs, _ := os.ReadDir(filepath.Join(packageDir, ocispec.ImageBlobsDir, "sha256")); len(blobs) != 0 {
		t.Errorf("pushed %d blobs, want none before every component can be packed", len(blobs))
	}
}

func TestPushRefusesAPackedBlobOutsideItsDirectories(t *testing.T) {
	component := cdx.Component{Type: cdx.ComponentTypeFile, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0"}
	elsewhere := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(elsewhere, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	packer := &fakePacker{pack: func(string, string) pluginlib.PackResult {
		manifest := pluginlib.PackedBlob{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			Size:      2,
			Path:      elsewhere,
		}
		return pluginlib.PackResult{Manifest: &manifest}
	}}
	reg := newRegistry(t)

	_, err := pushWithComponents(t, reg, transfer.Options{ComponentPacker: packer}, []cdx.Component{component}, []map[string]string{{"tool": "a"}})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("Push error = %v, want the blob refused as outside the pack's directories", err)
	}
	if _, err := reg.store("registry.example.com/packages/app").Resolve(context.Background(), packageRef); err == nil {
		t.Error("the package was tagged though a component's pack was refused")
	}
}

func TestPushPublishesWhatAPackerLeavesAsAnArtifactOfItsFiles(t *testing.T) {
	files := map[string]string{"bin/tool": "#!/bin/sh"}
	component := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "tool", Version: "1.0", PackageURL: "pkg:generic/tool@1.0"}
	packer := &fakePacker{}
	reg := newRegistry(t)

	result, err := pushWithComponents(t, reg, transfer.Options{ComponentPacker: packer}, []cdx.Component{component}, []map[string]string{files})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	var manifest ocispec.Manifest
	fetchJSON(t, reg.store("registry.example.com/packages/app/generic/tool"), "1.0", &manifest)
	if manifest.ArtifactType != ComponentArtifactType {
		t.Errorf("artifact type = %s, want bomify's own, for a pack of {}", manifest.ArtifactType)
	}
	want := map[string]string{
		ocispec.AnnotationCreated: "1970-01-01T00:00:00Z",
		AnnotationPackageDigest:   result.Manifest.Digest.String(),
		transfer.AnnotationPurl:   component.PackageURL,
	}
	if !maps.Equal(packer.annotations, want) {
		t.Errorf("pack was given annotations %v, want %v", packer.annotations, want)
	}
}
