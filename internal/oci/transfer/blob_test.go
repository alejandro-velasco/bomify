package transfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
)

// The component repositories push publishes to are remote repositories,
// which must stay MountTargets, or push would quietly stop mounting.
var _ MountTarget = (*remote.Repository)(nil)

// mountingTarget is a repository that can mount a blob: it records the
// repository it was asked to mount from, and either links the blob or, like
// a registry that won't mount, takes the upload getContent starts.
type mountingTarget struct {
	*oci.Store
	mounts int
	from   string
	// linked, if set, is the content a successful mount makes available.
	linked []byte
	// refusal, if set, is what the registry answers a mount with, instead
	// of starting an upload.
	refusal error
	// uploadFailure, if set, fails the upload the registry starts.
	uploadFailure error
}

func (m *mountingTarget) Mount(ctx context.Context, desc ocispec.Descriptor, fromRepo string, getContent func() (io.ReadCloser, error)) error {
	m.mounts++
	m.from = fromRepo
	if m.refusal != nil {
		return m.refusal
	}
	if m.linked != nil {
		return m.Store.Push(ctx, desc, bytes.NewReader(m.linked))
	}
	content, err := getContent()
	if err != nil {
		return err
	}
	defer content.Close()
	if m.uploadFailure != nil {
		if _, err := io.Copy(io.Discard, content); err != nil {
			return err
		}
		return m.uploadFailure
	}
	return m.Store.Push(ctx, desc, content)
}

// progressRecord records the progress bars a transfer opened.
type progressRecord struct {
	opened  int
	written int64
	closed  int
}

func (r *progressRecord) report(_ string, _ int64) io.WriteCloser {
	r.opened++
	return progressWriter{record: r}
}

type progressWriter struct{ record *progressRecord }

func (w progressWriter) Write(p []byte) (int, error) {
	w.record.written += int64(len(p))
	return len(p), nil
}

func (w progressWriter) Close() error {
	w.record.closed++
	return nil
}

// blobOf returns blob's descriptor, and an open that counts its calls.
func blobOf(blob []byte) (ocispec.Descriptor, func() (io.ReadCloser, error), *int) {
	desc := ocispec.Descriptor{
		MediaType: FileMediaType,
		Digest:    digest.FromBytes(blob),
		Size:      int64(len(blob)),
	}
	opened := 0
	open := func() (io.ReadCloser, error) {
		opened++
		return io.NopCloser(bytes.NewReader(blob)), nil
	}
	return desc, open, &opened
}

func newMountingTarget(t *testing.T) *mountingTarget {
	t.Helper()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &mountingTarget{Store: store}
}

func TestMountBlobMounts(t *testing.T) {
	blob := []byte("a large file")
	desc, open, opened := blobOf(blob)
	target := newMountingTarget(t)
	target.linked = blob
	var progress progressRecord

	if err := MountBlob(context.Background(), target, desc, "packages/app", open, "blob", progress.report); err != nil {
		t.Fatal(err)
	}

	if target.mounts != 1 || target.from != "packages/app" {
		t.Errorf("mounts = %d from %q, want one from packages/app", target.mounts, target.from)
	}
	if *opened != 0 || progress.opened != 0 {
		t.Errorf("opened the content %d times and %d bars, want neither for a mount", *opened, progress.opened)
	}
	if exists, err := target.Exists(context.Background(), desc); err != nil || !exists {
		t.Errorf("Exists = %v, %v, want the blob there", exists, err)
	}
}

func TestMountBlobUploadsWhenTheRegistryWontMount(t *testing.T) {
	blob := []byte("a large file")
	desc, open, opened := blobOf(blob)
	target := newMountingTarget(t)
	var progress progressRecord

	if err := MountBlob(context.Background(), target, desc, "packages/app", open, "blob", progress.report); err != nil {
		t.Fatal(err)
	}

	if target.mounts != 1 || *opened != 1 {
		t.Errorf("mounts = %d, opened = %d, want one each", target.mounts, *opened)
	}
	if progress.opened != 1 || progress.written != desc.Size || progress.closed != 1 {
		t.Errorf("progress = %+v, want one bar of %d bytes, closed", progress, desc.Size)
	}
	if exists, err := target.Exists(context.Background(), desc); err != nil || !exists {
		t.Errorf("Exists = %v, %v, want the blob there", exists, err)
	}
}

func TestMountBlobPushesWhenTheRegistryRefusesTheMount(t *testing.T) {
	blob := []byte("a large file")
	desc, open, opened := blobOf(blob)
	target := newMountingTarget(t)
	target.refusal = errors.New("405 method not allowed")
	var progress progressRecord

	if err := MountBlob(context.Background(), target, desc, "packages/app", open, "blob", progress.report); err != nil {
		t.Fatal(err)
	}

	if target.mounts != 1 || *opened != 1 {
		t.Errorf("mounts = %d, opened = %d, want one each", target.mounts, *opened)
	}
	if progress.opened != 1 || progress.written != desc.Size || progress.closed != 1 {
		t.Errorf("progress = %+v, want one bar of %d bytes, closed", progress, desc.Size)
	}
	if exists, err := target.Exists(context.Background(), desc); err != nil || !exists {
		t.Errorf("Exists = %v, %v, want the blob there", exists, err)
	}
}

func TestMountBlobFailsWhenTheRegistrysUploadDoes(t *testing.T) {
	blob := []byte("a large file")
	desc, open, opened := blobOf(blob)
	target := newMountingTarget(t)
	failure := errors.New("connection reset")
	target.uploadFailure = failure

	err := MountBlob(context.Background(), target, desc, "packages/app", open, "blob", nil)

	if !errors.Is(err, failure) {
		t.Errorf("MountBlob = %v, want %v", err, failure)
	}
	if *opened != 1 {
		t.Errorf("opened = %d, want one upload, not a second", *opened)
	}
}

func TestMountBlobSkipsABlobTheTargetHas(t *testing.T) {
	blob := []byte("a large file")
	desc, open, opened := blobOf(blob)
	target := newMountingTarget(t)
	if err := target.Store.Push(context.Background(), desc, bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}

	if err := MountBlob(context.Background(), target, desc, "packages/app", open, "blob", nil); err != nil {
		t.Fatal(err)
	}

	if target.mounts != 0 || *opened != 0 {
		t.Errorf("mounts = %d, opened = %d, want neither for a blob already there", target.mounts, *opened)
	}
}
