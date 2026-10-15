package push

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// manifestMediaTypes are what a registry stores as a manifest, never as a
// blob it can mount: OCI's and Docker's manifests and indexes.
var manifestMediaTypes = []string{
	ocispec.MediaTypeImageManifest,
	ocispec.MediaTypeImageIndex,
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}

// packedPublisher publishes a component as its packer packed it (see
// transfer.ComponentPacker): an artifact in its kind's own registry format,
// such as an image or a Helm chart, copied as it is.
type packedPublisher struct {
	componentPublication
	manifest ocispec.Descriptor
	blobs    packedBlobs
}

// newPackedPublisher returns the publisher of publication as packed, whose
// blobs are files in publication's directory or output, where its pack
// wrote the blobs it built.
func newPackedPublisher(publication componentPublication, packed pluginlib.PackResult, output string) (packedPublisher, error) {
	manifest, err := packedDescriptor(*packed.Manifest)
	if err != nil {
		return packedPublisher{}, err
	}
	blobs := packedBlobs{}
	for _, blob := range append([]pluginlib.PackedBlob{*packed.Manifest}, packed.Blobs...) {
		if err := blobs.add(blob, publication.dir(), output); err != nil {
			return packedPublisher{}, err
		}
	}
	publisher := packedPublisher{
		componentPublication: publication,
		manifest:             manifest,
		blobs:                blobs,
	}
	return publisher, nil
}

// publish copies the packed artifact to target with oras.CopyGraph, which
// pushes what a manifest names before the manifest, so target never holds
// a manifest it lacks the content of, skips what target already has, and
// copies up to opts.Concurrency blobs at once. Each blob is pushed here, as
// transfer.MountBlob pushes one, so a blob the package already pushed, such
// as a large image layer, is mounted from the package's repository rather
// than uploaded again, and each upload shows its progress.
func (p packedPublisher) publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	pushBlob := func(ctx context.Context, desc ocispec.Descriptor) error {
		// A registry mounts only blobs, though a manifest may match a large
		// file the package pushed.
		from := p.mountFrom()
		if slices.Contains(manifestMediaTypes, desc.MediaType) {
			from = ""
		}
		open := func() (io.ReadCloser, error) {
			return p.blobs.Fetch(ctx, desc)
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
	if err := oras.CopyGraph(ctx, p.blobs, target, p.manifest, copyOpts); err != nil {
		return ocispec.Descriptor{}, err
	}
	return p.manifest, nil
}

// packedBlobs are a PackResult's blobs, by digest: a read-only content
// store over the files that hold them.
type packedBlobs map[digest.Digest]pluginlib.PackedBlob

// add adds blob to b, checking that it's a valid descriptor whose file,
// within input or output, holds exactly its size.
func (b packedBlobs) add(blob pluginlib.PackedBlob, input, output string) error {
	desc, err := packedDescriptor(blob)
	if err != nil {
		return err
	}
	if !within(blob.Path, input) && !within(blob.Path, output) {
		return fmt.Errorf("blob %s is at %s, outside %s and %s", blob.Digest, blob.Path, input, output)
	}
	info, err := os.Stat(blob.Path)
	if err != nil {
		return fmt.Errorf("blob %s: %w", blob.Digest, err)
	}
	if !info.Mode().IsRegular() || info.Size() != blob.Size {
		return fmt.Errorf("blob %s: %s isn't a file of %d bytes", blob.Digest, blob.Path, blob.Size)
	}
	b[desc.Digest] = blob
	return nil
}

// Fetch opens the file holding desc's bytes, read no further than its
// size.
func (b packedBlobs) Fetch(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	blob, ok := b[desc.Digest]
	if !ok {
		return nil, fmt.Errorf("%s: %w: the pack lists no such blob", desc.Digest, errdef.ErrNotFound)
	}
	file, err := os.Open(blob.Path)
	if err != nil {
		return nil, err
	}
	limited := limitedFile{
		Reader: io.LimitReader(file, blob.Size),
		Closer: file,
	}
	return limited, nil
}

// Exists reports whether the pack lists desc.
func (b packedBlobs) Exists(_ context.Context, desc ocispec.Descriptor) (bool, error) {
	_, ok := b[desc.Digest]
	return ok, nil
}

// packedDescriptor returns blob's descriptor, checking its digest.
func packedDescriptor(blob pluginlib.PackedBlob) (ocispec.Descriptor, error) {
	parsed, err := digest.Parse(blob.Digest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("blob %q: %w", blob.Digest, err)
	}
	desc := ocispec.Descriptor{
		MediaType: blob.MediaType,
		Digest:    parsed,
		Size:      blob.Size,
	}
	return desc, nil
}

// within reports whether path is dir or inside it.
func within(path, dir string) bool {
	relative, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
