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
		// Two layers can share a blob (identical parts of a large file,
		// say) and be pushed at once: whichever finishes second finds the
		// other's copy, which is just as good.
		if errors.Is(err, errdef.ErrAlreadyExists) {
			return nil
		}
		return fmt.Errorf("push %s: %w", desc.Digest, err)
	}
	return nil
}

// PartLabel names one of a large file's part layers (see
// FilePartMediaType) in progress output: the file's path, which of its
// count parts it is, from 1, when there's more than one, and then its
// component's purl. The path comes first so it survives a long label
// being cut short, and tells the bars of one component's files apart.
func PartLabel(purl, path string, number, count int) string {
	if count > 1 {
		path = fmt.Sprintf("%s %d/%d", path, number, count)
	}
	return path + " " + purl
}

// Label names a component's blob in progress output and errors: its purl,
// or hash when it has none.
func Label(purl, hash string) string {
	if purl == "" {
		return hash
	}
	return purl
}
