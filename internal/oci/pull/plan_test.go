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

func TestPlanComponent(t *testing.T) {
	descs := []ocispec.Descriptor{
		layerOf(transfer.LayerMediaType, "model"),
		fileOf("weights.bin"),
		fileOf("dir/other.bin"),
	}

	layers, err := planComponent(descs)
	if err != nil {
		t.Fatalf("planComponent: %v", err)
	}

	// One per layer, in order.
	var labels []string
	for _, layer := range layers {
		labels = append(labels, layer.label("p"))
	}
	want := []string{
		"p",
		"weights.bin p",
		"dir/other.bin p",
	}
	if !slices.Equal(labels, want) {
		t.Errorf("layers' labels = %q, want %q", labels, want)
	}
}

func TestPlanComponentRejects(t *testing.T) {
	escaping := fileOf("../weights.bin")
	for name, tc := range map[string]struct {
		descs []ocispec.Descriptor
		want  string
	}{
		"an escaping path": {[]ocispec.Descriptor{escaping}, "outside its component"},
		"one path twice":   {[]ocispec.Descriptor{fileOf("weights.bin"), fileOf("weights.bin")}, "two layers hold weights.bin"},
	} {
		if _, err := planComponent(tc.descs); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: planComponent = %v, want an error containing %q", name, err, tc.want)
		}
	}
}
