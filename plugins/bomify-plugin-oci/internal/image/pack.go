package image

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// Pack describes the image of the OCI image layout a prior Pull wrote into
// inputDir as it is: its manifest, config, and layers, each the layout's
// own file, so publishing it keeps the image's digest. It builds nothing,
// so it writes nothing.
func Pack(inputDir string, logger *slog.Logger) (*plugin.PackResult, error) {
	image, err := layoutImage(inputDir)
	if err != nil {
		return nil, err
	}
	manifest, err := readManifest(inputDir, image)
	if err != nil {
		return nil, err
	}

	manifestBlob := blobOf(inputDir, image)
	blobs := []plugin.PackedBlob{blobOf(inputDir, manifest.Config)}
	for _, layer := range manifest.Layers {
		blobs = append(blobs, blobOf(inputDir, layer))
	}
	result := plugin.PackResult{
		Manifest: &manifestBlob,
		Blobs:    blobs,
	}
	logger.Info("packed image", "digest", manifestBlob.Digest, "layers", len(manifest.Layers))
	return &result, nil
}

// layoutImage returns the descriptor of the one image the OCI image layout
// in dir holds, without the annotations its index gives it, which aren't
// the image's own.
func layoutImage(dir string) (ocispec.Descriptor, error) {
	data, err := os.ReadFile(filepath.Join(dir, ocispec.ImageIndexFile))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read the image's OCI layout: %w", err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse the image's OCI layout: %w", err)
	}
	if len(index.Manifests) != 1 {
		return ocispec.Descriptor{}, fmt.Errorf("the image's OCI layout holds %d images, want one", len(index.Manifests))
	}
	image := ocispec.Descriptor{
		MediaType: index.Manifests[0].MediaType,
		Digest:    index.Manifests[0].Digest,
		Size:      index.Manifests[0].Size,
	}
	return image, nil
}

// readManifest reads image's manifest, an OCI or Docker one, from the
// layout in dir. Pull stores one platform's image, so anything else, such
// as an index, is refused.
func readManifest(dir string, image ocispec.Descriptor) (ocispec.Manifest, error) {
	if !types.MediaType(image.MediaType).IsImage() {
		return ocispec.Manifest{}, fmt.Errorf("the image's OCI layout holds a %s, not an image manifest", image.MediaType)
	}
	data, err := os.ReadFile(blobPath(dir, image))
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("read %s: %w", image.Digest, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ocispec.Manifest{}, fmt.Errorf("parse %s: %w", image.Digest, err)
	}
	return manifest, nil
}

// blobOf returns desc as a pack's blob: the layout in dir's file of it
// (see blobPath).
func blobOf(dir string, desc ocispec.Descriptor) plugin.PackedBlob {
	blob := plugin.PackedBlob{
		MediaType: desc.MediaType,
		Digest:    desc.Digest.String(),
		Size:      desc.Size,
		Path:      blobPath(dir, desc),
	}
	return blob
}

// blobPath returns the path of the OCI image layout in dir's file of the
// blob desc names: blobs/<algorithm>/<encoded digest>.
func blobPath(dir string, desc ocispec.Descriptor) string {
	return filepath.Join(dir, ocispec.ImageBlobsDir, desc.Digest.Algorithm().String(), desc.Digest.Encoded())
}
