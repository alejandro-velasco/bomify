package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
)

// Tests of how transfer fails: a target that errors, a referrer or layer
// bigger than allowed or that isn't there, and an archive it can't write.

var errInjected = errors.New("injected")

// failingTarget is a store that fails as told: Exists with existsErr,
// and Push of a blob of failMediaType (any, if empty) with pushErr.
type failingTarget struct {
	*memory.Store
	existsErr     error
	pushErr       error
	failMediaType string
}

func newFailingTarget() *failingTarget {
	return &failingTarget{Store: memory.New()}
}

func (f *failingTarget) Exists(ctx context.Context, desc ocispec.Descriptor) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.Store.Exists(ctx, desc)
}

func (f *failingTarget) Push(ctx context.Context, desc ocispec.Descriptor, r io.Reader) error {
	if f.pushErr != nil && (f.failMediaType == "" || desc.MediaType == f.failMediaType) {
		return f.pushErr
	}
	return f.Store.Push(ctx, desc, r)
}

// notGraph is a target that can't list referrers.
type notGraph struct {
	oras.Target
}

// wantError fails t unless err contains want.
func wantError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("error = %v, want one containing %q", err, want)
	}
}

func TestPushBlobFails(t *testing.T) {
	ctx := context.Background()
	data := []byte("blob")

	cantCheck := newFailingTarget()
	cantCheck.existsErr = errInjected
	_, err := PushBytes(ctx, cantCheck, data, FileMediaType, "blob", nil)
	wantError(t, err, "check")

	cantPush := newFailingTarget()
	cantPush.pushErr = errInjected
	_, err = PushBytes(ctx, cantPush, data, FileMediaType, "blob", nil)
	wantError(t, err, "push")
}

// TestPushBlobToleratesAConcurrentPush covers two pushes of one blob at
// once: whichever finishes second finds the other's copy, which is just
// as good.
func TestPushBlobToleratesAConcurrentPush(t *testing.T) {
	target := newFailingTarget()
	target.pushErr = fmt.Errorf("pushed meanwhile: %w", errdef.ErrAlreadyExists)

	if _, err := PushBytes(context.Background(), target, []byte("blob"), FileMediaType, "blob", nil); err != nil {
		t.Errorf("PushBytes = %v, want nil", err)
	}
}

func TestMountBlobFailsToOpen(t *testing.T) {
	desc, _, _ := blobOf([]byte("blob"))
	open := func() (io.ReadCloser, error) { return nil, errInjected }

	err := MountBlob(context.Background(), memory.New(), desc, "", open, "blob", nil)

	if !errors.Is(err, errInjected) {
		t.Errorf("MountBlob = %v, want the open's error", err)
	}
}

func TestPushReferrerFails(t *testing.T) {
	ctx := context.Background()
	subject := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("subject"), Size: 7}

	cantPushConfig := newFailingTarget()
	cantPushConfig.pushErr = errInjected
	cantPushConfig.failMediaType = ocispec.MediaTypeEmptyJSON
	_, err := PushReferrer(ctx, cantPushConfig, subject, "application/vnd.test", nil, nil, "test")
	wantError(t, err, "push empty config")

	cantPushManifest := newFailingTarget()
	cantPushManifest.pushErr = errInjected
	cantPushManifest.failMediaType = ocispec.MediaTypeImageManifest
	_, err = PushReferrer(ctx, cantPushManifest, subject, "application/vnd.test", nil, nil, "test")
	wantError(t, err, "push test referrer")
}

func TestReferrersFails(t *testing.T) {
	subject := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("subject"), Size: 7}

	_, err := Referrers(context.Background(), notGraph{memory.New()}, subject, "")

	wantError(t, err, "cannot list referrers")
}

func TestReferrerLayersFails(t *testing.T) {
	ctx := context.Background()
	store, _ := newPackage(t)

	_, err := ReferrerLayers(ctx, store, ocispec.Descriptor{Digest: digest.FromString("big"), Size: maxReferrerManifestSize + 1}, "")
	wantError(t, err, "larger than")

	_, err = ReferrerLayers(ctx, store, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("gone"), Size: 4}, "")
	wantError(t, err, "fetch referrer")

	data := []byte("not a manifest")
	notJSON := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(data), Size: int64(len(data))}
	_, err = ReferrerLayers(ctx, rawStorage(data), notJSON, "")
	wantError(t, err, "parse referrer")
}

// rawStorage serves its bytes for any blob, as rawFetcher does, and has
// every blob.
type rawStorage []byte

func (s rawStorage) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s)), nil
}

func (s rawStorage) Exists(context.Context, ocispec.Descriptor) (bool, error) {
	return true, nil
}

func TestFetchAttachmentFails(t *testing.T) {
	ctx := context.Background()
	store, subject := newPackage(t)
	layer := func(data []byte) ocispec.Descriptor {
		desc, err := PushBytes(ctx, store, data, "text/plain", "layer", nil)
		if err != nil {
			t.Fatal(err)
		}
		return desc
	}
	referrer := func(layers ...ocispec.Descriptor) ocispec.Descriptor {
		desc, err := PushReferrer(ctx, store, subject, "application/vnd.test", layers, nil, "test")
		if err != nil {
			t.Fatal(err)
		}
		return desc
	}
	huge := layer([]byte("huge"))
	huge.Size = maxReferrerLayerSize + 1
	missing := ocispec.Descriptor{MediaType: "text/plain", Digest: digest.FromString("gone"), Size: 4}

	for name, test := range map[string]struct {
		referrer ocispec.Descriptor
		want     string
	}{
		"no layer":        {referrer: referrer(), want: "0 matching layers"},
		"two layers":      {referrer: referrer(layer([]byte("a")), layer([]byte("b"))), want: "2 matching layers"},
		"a layer too big": {referrer: referrer(huge), want: "larger than"},
		"a missing layer": {referrer: referrer(missing), want: "fetch layer"},
		"a missing referrer": {
			referrer: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("gone"), Size: 4},
			want:     "fetch referrer",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := FetchAttachment(ctx, store, test.referrer, "text/plain")

			wantError(t, err, test.want)
		})
	}
}

func TestAttachFails(t *testing.T) {
	ctx := context.Background()
	document := Attachment{ArtifactType: "application/vnd.test", MediaType: "text/plain", Name: "doc", Data: []byte("doc")}

	cantPushDocument := newFailingTarget()
	cantPushDocument.pushErr = errInjected
	cantPushDocument.failMediaType = "text/plain"
	_, _, err := Attach(ctx, cantPushDocument, ocispec.Descriptor{}, document, nil)
	wantError(t, err, "push doc")

	_, _, err = Attach(ctx, notGraph{memory.New()}, ocispec.Descriptor{}, document, nil)
	wantError(t, err, "cannot list referrers")

	cantPushReferrer := newFailingTarget()
	cantPushReferrer.pushErr = errInjected
	cantPushReferrer.failMediaType = ocispec.MediaTypeImageManifest
	subject := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("subject"), Size: 7}
	_, _, err = Attach(ctx, cantPushReferrer, subject, document, nil)
	wantError(t, err, "push doc referrer")
}

// TestAttachFailsOnAnUnreadableReferrer covers a referrer already
// attached whose manifest is gone: listing the package's referrers reads
// it, and fails.
func TestAttachFailsOnAnUnreadableReferrer(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := oci.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document := Attachment{ArtifactType: "application/vnd.test", MediaType: "text/plain", Name: "doc", Data: []byte("doc")}
	if _, _, err := Attach(ctx, store, subject, document, nil); err != nil {
		t.Fatal(err)
	}
	referrers, err := Referrers(ctx, store, subject, document.ArtifactType)
	if err != nil || len(referrers) != 1 {
		t.Fatalf("Referrers = %v, %v", referrers, err)
	}
	// The store's copy of the referrer, gone: its layers can't be read.
	if err := os.Remove(filepath.Join(dir, "blobs", "sha256", referrers[0].Digest.Encoded())); err != nil {
		t.Fatal(err)
	}

	_, _, err = Attach(ctx, store, subject, Attachment{ArtifactType: document.ArtifactType, MediaType: "text/plain", Name: "other", Data: []byte("other")}, nil)

	wantError(t, err, "list application/vnd.test referrers")
}

func TestWriteTarFails(t *testing.T) {
	err := WriteTar(filepath.Join(t.TempDir(), "missing"), io.Discard)
	if err == nil {
		t.Error("WriteTar of a missing directory succeeded")
	}

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "file.txt"), "content")
	err = WriteTar(dir, failingWriter{})
	if !errors.Is(err, errInjected) {
		t.Errorf("WriteTar to a failing writer = %v, want its error", err)
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errInjected }
