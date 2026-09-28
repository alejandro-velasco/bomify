package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
)

// PushBytes pushes data to target as a single blob of the given media
// type, reporting its progress through progress under label, and returns
// its descriptor. A blob target already has is not re-pushed.
func PushBytes(ctx context.Context, target oras.Target, data []byte, mediaType, label string, progress ProgressFunc) (ocispec.Descriptor, error) {
	if progress == nil {
		progress = Discard
	}

	sum := sha256.Sum256(data)
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.NewDigestFromBytes(digest.SHA256, sum[:]),
		Size:      int64(len(data)),
	}

	// A remote registry tolerates re-pushing a blob whose digest it
	// already has, but a local content/oci.Store — as used when Save
	// packages more than one tag sharing a component into the same
	// store — rejects it outright. Checking first makes either target
	// happy, and avoids re-uploading identical content to a registry
	// that already has it.
	if exists, err := target.Exists(ctx, desc); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("check %s: %w", desc.Digest, err)
	} else if exists {
		return desc, nil
	}

	pw := progress(label, desc.Size)
	defer pw.Close()

	if err := target.Push(ctx, desc, io.TeeReader(bytes.NewReader(data), pw)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", desc.Digest, err)
	}

	return desc, nil
}
