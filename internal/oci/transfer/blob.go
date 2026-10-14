package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
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
	if err := PushBlob(ctx, target, desc, bytes.NewReader(data), label, progress); err != nil {
		return ocispec.Descriptor{}, err
	}
	return desc, nil
}

// PushBlob pushes r's content — desc's — to target, reporting its
// progress through progress under label, unless target already has it.
func PushBlob(ctx context.Context, target oras.Target, desc ocispec.Descriptor, r io.Reader, label string, progress ProgressFunc) error {
	if progress == nil {
		progress = Discard
	}

	// A remote registry tolerates re-pushing a blob whose digest it
	// already has, but a local content/oci.Store — as used when Save
	// packages more than one tag sharing a component into the same
	// store — rejects it outright. Checking first makes either target
	// happy, and avoids re-uploading identical content to a registry
	// that already has it.
	if exists, err := target.Exists(ctx, desc); err != nil {
		return fmt.Errorf("check %s: %w", desc.Digest, err)
	} else if exists {
		return nil
	}

	pw := progress(label, desc.Size)
	defer pw.Close()

	if err := target.Push(ctx, desc, io.TeeReader(r, pw)); err != nil {
		// Two layers can share a blob (two identical large files, say) and
		// be pushed at once: whichever finishes second finds the
		// other's copy, which is just as good.
		if errors.Is(err, errdef.ErrAlreadyExists) {
			return nil
		}
		return fmt.Errorf("push %s: %w", desc.Digest, err)
	}
	return nil
}

// LayerLabel names one of a component's layers, a tar or a large file, in
// progress output: its short digest, which tells the component's layers
// apart, then the component's purl, or just hash when it has none. The
// digest comes first, at a fixed width, so it survives a long purl being
// cut short.
func LayerLabel(purl, hash string) string {
	if purl == "" {
		return hash
	}
	return hash[:shortHashLen] + " " + purl
}

// shortHashLen is how many hex characters of a hash LayerLabel shows, as
// many as a short image ID.
const shortHashLen = 12

// Label names a component's blob in progress output and errors: its purl,
// or hash when it has none.
func Label(purl, hash string) string {
	if purl == "" {
		return hash
	}
	return purl
}
