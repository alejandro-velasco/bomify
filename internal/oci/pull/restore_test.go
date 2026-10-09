package pull

import (
	"reflect"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

func layerOf(mediaType, purl string) ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType:   mediaType,
		Digest:      digest.FromString(mediaType + purl),
		Annotations: map[string]string{},
	}
	if purl != "" {
		desc.Annotations[transfer.AnnotationPurl] = purl
	}
	return desc
}

func TestGroupLayers(t *testing.T) {
	descs := []ocispec.Descriptor{
		0: layerOf(transfer.LayerMediaType, "model"),
		1: layerOf(transfer.LayerMediaType, "app"),
		2: layerOf(transfer.FilePartMediaType, "model"),
		3: layerOf(transfer.FilePartMediaType, "model"),
		4: layerOf("application/x-foo", ""),
		5: layerOf(transfer.FilePartMediaType, "model"),
		// A purl alone doesn't make a layer a component's.
		6: layerOf("application/x-foo", "app"),
		// Nor does a component media type without a purl.
		7: layerOf(transfer.LayerMediaType, ""),
	}

	groups, foreign := groupLayers(descs)

	wantGroups := []layerGroup{
		{purl: "model", manifestIndexes: []int{0, 2, 3, 5}},
		{purl: "app", manifestIndexes: []int{1}},
	}
	if !reflect.DeepEqual(groups, wantGroups) {
		t.Errorf("groups = %+v, want %+v", groups, wantGroups)
	}
	if want := []int{4, 6, 7}; !reflect.DeepEqual(foreign, want) {
		t.Errorf("foreign = %v, want %v", foreign, want)
	}
}

func TestGroupLayersEmpty(t *testing.T) {
	groups, foreign := groupLayers(nil)
	if groups != nil || foreign != nil {
		t.Errorf("groupLayers(nil) = %v, %v; want nothing", groups, foreign)
	}
}
