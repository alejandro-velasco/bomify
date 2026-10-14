package pull

import (
	"slices"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

func fileOf(path string) ocispec.Descriptor {
	desc := layerOf(transfer.FileMediaType, "model")
	desc.Annotations[transfer.AnnotationFilePath] = path
	desc.Annotations[transfer.AnnotationFileMode] = "0644"
	return desc
}

func TestNewComponentLayers(t *testing.T) {
	descs := []ocispec.Descriptor{
		layerOf(transfer.LayerMediaType, "model"),
		fileOf("weights.bin"),
		fileOf("dir/other.bin"),
	}

	layers, err := newComponentLayers(descs)
	if err != nil {
		t.Fatalf("newComponentLayers: %v", err)
	}

	// One per layer, in order.
	var kinds []string
	for _, layer := range layers {
		switch layer := layer.(type) {
		case tarLayer:
			kinds = append(kinds, "tar")
		case fileLayer:
			kinds = append(kinds, "file "+layer.file.Path)
		}
	}
	want := []string{
		"tar",
		"file weights.bin",
		"file dir/other.bin",
	}
	if !slices.Equal(kinds, want) {
		t.Errorf("layers = %q, want %q", kinds, want)
	}
}

func TestNewComponentLayersRejects(t *testing.T) {
	escaping := fileOf("../weights.bin")
	for name, tc := range map[string]struct {
		descs []ocispec.Descriptor
		want  string
	}{
		"an escaping path": {[]ocispec.Descriptor{escaping}, "outside its component"},
		"one path twice":   {[]ocispec.Descriptor{fileOf("weights.bin"), fileOf("weights.bin")}, "two layers hold weights.bin"},
		"a foreign layer":  {[]ocispec.Descriptor{layerOf("application/octet-stream", "model")}, "isn't a component layer's"},
	} {
		if _, err := newComponentLayers(tc.descs); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: newComponentLayers = %v, want an error containing %q", name, err, tc.want)
		}
	}
}
