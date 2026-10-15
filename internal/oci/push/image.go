package push

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// manifestMediaTypes are what a registry stores as a manifest, never as a
// blob it can mount: OCI's and Docker's manifests and indexes.
var manifestMediaTypes = []string{
	ocispec.MediaTypeImageManifest,
	ocispec.MediaTypeImageIndex,
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}

// imagePublisher publishes an image component as it is: the one image of
// the OCI image layout its plugin stored, copied blob by blob, so it keeps
// its digest.
type imagePublisher struct{ componentPublication }

// publish copies the image to target with oras.CopyGraph, which pushes
// what a manifest names before the manifest, so target never holds a
// manifest it lacks the content of, skips what target already has, and
// copies up to opts.Concurrency blobs at once. Each blob is pushed here,
// as transfer.MountBlob pushes one, so a layer the package already pushed
// is mounted from the package's repository rather than uploaded again, and
// each upload shows its progress.
func (p imagePublisher) publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	dir := p.dir()
	image, err := layoutImage(dir)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	store, err := oci.NewFromFS(ctx, os.DirFS(dir))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read the image's OCI layout: %w", err)
	}

	pushBlob := func(ctx context.Context, desc ocispec.Descriptor) error {
		// A registry mounts only blobs, though a manifest may match a large
		// file the package pushed.
		from := p.mountFrom()
		if slices.Contains(manifestMediaTypes, desc.MediaType) {
			from = ""
		}
		open := func() (io.ReadCloser, error) {
			return store.Fetch(ctx, desc)
		}
		label := transfer.LayerLabel(p.component.PackageURL, desc.Digest.Encoded()) + componentRepositoryLabel
		if err := transfer.MountBlob(ctx, target, desc, from, open, label, p.opts.Progress); err != nil {
			return err
		}
		// Now in target, so CopyGraph doesn't copy it again.
		return oras.SkipNode
	}
	copyOpts := oras.CopyGraphOptions{
		Concurrency: p.opts.Concurrency,
		PreCopy:     pushBlob,
	}
	if err := oras.CopyGraph(ctx, store, target, image, copyOpts); err != nil {
		return ocispec.Descriptor{}, err
	}
	return image, nil
}

// layoutImage returns the descriptor of the one image the OCI image
// layout in dir holds, without the annotations its index gives it, which
// aren't the image's own.
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

	desc := ocispec.Descriptor{
		MediaType: index.Manifests[0].MediaType,
		Digest:    index.Manifests[0].Digest,
		Size:      index.Manifests[0].Size,
	}
	return desc, nil
}
