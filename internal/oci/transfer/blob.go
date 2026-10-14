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
	"oras.land/oras-go/v2/registry"
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

// MountTarget is a target that can mount a blob from another repository
// of its registry: a remote repository, not a local store.
type MountTarget interface {
	oras.Target
	registry.Mounter
}

// MountBlob makes desc available in target by asking the registry to mount
// it from the repository from, another of the registry's that already
// holds it, instead of uploading it, so a blob a registry stores once is
// sent once. A registry that can't or won't mount should answer by starting
// an upload, and one that refuses the request outright gets the blob pushed
// as PushBlob pushes it, so the blob ends up in target either way. open
// returns the blob's content, and is only called to upload it, which alone
// shows progress under label.
func MountBlob(ctx context.Context, target MountTarget, desc ocispec.Descriptor, from string, open func() (io.ReadCloser, error), label string, progress ProgressFunc) error {
	if progress == nil {
		progress = Discard
	}

	// Mounting a blob the target already has is wasted, and a local store
	// would reject it, as PushBlob explains.
	if exists, err := target.Exists(ctx, desc); err != nil {
		return fmt.Errorf("check %s: %w", desc.Digest, err)
	} else if exists {
		return nil
	}

	// The registry asks for the content only if it started an upload
	// instead of mounting the blob.
	var uploading bool
	getContent := func() (io.ReadCloser, error) {
		uploading = true
		content, err := open()
		if err != nil {
			return nil, err
		}
		pw := progress(label, desc.Size)
		reported := reportedContent{
			Reader:   io.TeeReader(content, pw),
			content:  content,
			progress: pw,
		}
		return reported, nil
	}
	err := target.Mount(ctx, desc, from, getContent)
	if err == nil || errors.Is(err, errdef.ErrAlreadyExists) {
		return nil
	}
	if uploading {
		return fmt.Errorf("upload %s: %w", desc.Digest, err)
	}

	// The spec asks a registry that won't mount to start an upload, but
	// some refuse the request instead (an unsupported method, say).
	content, err := open()
	if err != nil {
		return err
	}
	defer content.Close()
	return PushBlob(ctx, target, desc, content, label, progress)
}

// reportedContent is a blob's content, reporting what is read of it
// through progress, closing both when it is.
type reportedContent struct {
	io.Reader
	content  io.Closer
	progress io.Closer
}

func (c reportedContent) Close() error {
	return errors.Join(c.content.Close(), c.progress.Close())
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
