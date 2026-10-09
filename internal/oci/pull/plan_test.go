package pull

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

func partOf(path string, size, offset, length int64) ocispec.Descriptor {
	desc := layerOf(transfer.FilePartMediaType, "model")
	desc.Size = length
	desc.Annotations[transfer.AnnotationFilePath] = path
	desc.Annotations[transfer.AnnotationFileMode] = "0644"
	desc.Annotations[transfer.AnnotationFileSize] = strconv.FormatInt(size, 10)
	desc.Annotations[transfer.AnnotationFileOffset] = strconv.FormatInt(offset, 10)
	return desc
}

func TestPlanComponent(t *testing.T) {
	descs := []ocispec.Descriptor{
		layerOf(transfer.LayerMediaType, "model"),
		// weights.bin's parts, out of order.
		partOf("weights.bin", 10, 6, 4),
		partOf("weights.bin", 10, 0, 6),
		partOf("dir/other.bin", 3, 0, 3),
	}

	plan, err := planComponent(descs)
	if err != nil {
		t.Fatalf("planComponent: %v", err)
	}

	// One transfer per layer: the tar, then each file's parts by offset,
	// numbered, whatever order the layers came in.
	var labels []string
	for _, layerTransfer := range plan.transfers {
		labels = append(labels, layerTransfer.label("p"))
	}
	want := []string{
		"p",
		"weights.bin 1/2 p",
		"weights.bin 2/2 p",
		"dir/other.bin p",
	}
	if !slices.Equal(labels, want) {
		t.Errorf("transfers' labels = %q, want %q", labels, want)
	}

	// One file per path, its parts by offset.
	if len(plan.files) != 2 {
		t.Fatalf("got %d files, want 2", len(plan.files))
	}
	weights := plan.files[0]
	if weights.path != "weights.bin" || weights.size != 10 || weights.mode != 0o644 {
		t.Errorf("file = %+v, want weights.bin, 10 bytes, 0644", weights)
	}
	if offsets := []int64{weights.parts[0].offset, weights.parts[1].offset}; offsets[0] != 0 || offsets[1] != 6 {
		t.Errorf("weights.bin's part offsets = %v, want [0 6]", offsets)
	}
}

func TestPlanComponentRejectsOtherMediaTypes(t *testing.T) {
	descs := []ocispec.Descriptor{layerOf("application/x-foo", "model")}
	if _, err := planComponent(descs); err == nil || !strings.Contains(err.Error(), "not a component layer") {
		t.Errorf("planComponent = %v, want the layer refused", err)
	}
}
