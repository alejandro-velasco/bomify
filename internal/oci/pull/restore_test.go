package pull

import (
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
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

func TestPackageRestores(t *testing.T) {
	descs := []ocispec.Descriptor{
		0: layerOf(transfer.LayerMediaType, "model"),
		1: layerOf(transfer.LayerMediaType, "app"),
		2: layerOf(transfer.FileMediaType, "model"),
		3: layerOf(transfer.FileMediaType, "model"),
		4: layerOf("application/x-foo", ""),
		5: layerOf(transfer.FileMediaType, "model"),
		// A purl alone doesn't make a layer a component's.
		6: layerOf("application/x-foo", "app"),
		// Nor does a component media type without a purl.
		7: layerOf(transfer.LayerMediaType, ""),
	}

	// Only model is in the SBOM.
	model := cdx.Component{
		Name:       "model",
		PackageURL: "model",
	}
	restore := packageRestore{
		descs:            descs,
		componentsByPurl: map[string]*cdx.Component{"model": &model},
	}
	restores := restore.restores()

	// In the order each first appears.
	want := []layerRestore{
		&componentRestore{purl: "model", descs: []ocispec.Descriptor{descs[0], descs[2], descs[3], descs[5]}, component: &model},
		&componentRestore{purl: "app", descs: []ocispec.Descriptor{descs[1]}},
		foreignRestore{desc: descs[4]},
		foreignRestore{desc: descs[6]},
		foreignRestore{desc: descs[7]},
	}
	if !reflect.DeepEqual(restores, want) {
		t.Errorf("restores = %+v, want %+v", restores, want)
	}
}

func TestPackageRestoresEmpty(t *testing.T) {
	var restore packageRestore
	if restores := restore.restores(); restores != nil {
		t.Errorf("restores() = %v, want nothing", restores)
	}
}
