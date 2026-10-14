package push

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
)

// imagePublisher publishes an image component as it is.
type imagePublisher struct{ componentPublication }

// publish copies the image p's component's plugin stored, the one image
// of an OCI image layout, to target as it is, so it keeps its digest.
func (p imagePublisher) publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	dir := p.dir()
	desc, err := layoutImage(dir)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	store, err := oci.NewFromFS(ctx, os.DirFS(dir))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read the image's OCI layout: %w", err)
	}
	if err := p.copyImage(ctx, store, target, desc); err != nil {
		return ocispec.Descriptor{}, err
	}
	return desc, nil
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

// copyImage copies desc, and everything it refers to, from src to target,
// up to opts.Concurrency blobs at once: what a manifest names before the
// manifest, so target never holds a manifest it lacks the content of, and
// nothing under one target already has. A layer the package already
// pushed is mounted from the package's repository instead of uploaded
// again (see mountSource).
func (p imagePublisher) copyImage(ctx context.Context, src content.ReadOnlyStorage, target oras.Target, desc ocispec.Descriptor) error {
	if exists, err := target.Exists(ctx, desc); err != nil {
		return fmt.Errorf("check %s: %w", desc.Digest, err)
	} else if exists {
		return nil
	}

	successors, err := content.Successors(ctx, src, desc)
	if err != nil {
		return fmt.Errorf("read %s: %w", desc.Digest, err)
	}
	copySuccessor := func(ctx context.Context, _ int, successor ocispec.Descriptor) error {
		return p.copyImage(ctx, src, target, successor)
	}
	if err := parallel.ForEach(ctx, p.opts.Concurrency, successors, copySuccessor); err != nil {
		return err
	}

	// Only a blob can be mounted, not a manifest, which refers to its
	// config and layers.
	var from string
	if len(successors) == 0 {
		from = p.mountSource(desc)
	}
	open := func() (io.ReadCloser, error) {
		blob, err := src.Fetch(ctx, desc)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", desc.Digest, err)
		}
		return blob, nil
	}
	label := transfer.LayerLabel(p.component.PackageURL, desc.Digest.Encoded()) + componentRepositoryLabel
	return p.pushBlob(ctx, target, desc, from, open, label)
}
