package transfer

import (
	"context"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
)

// newPackage returns an OCI layout store holding one empty package
// manifest, for referrers to attach to.
func newPackage(t *testing.T) (*oci.Store, ocispec.Descriptor) {
	t.Helper()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	manifest, err := oras.PackManifest(context.Background(), store, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{})
	if err != nil {
		t.Fatalf("pack package manifest: %v", err)
	}
	return store, manifest
}

func TestAttach(t *testing.T) {
	ctx := context.Background()
	store, manifest := newPackage(t)
	doc := func(name, data string) Attachment {
		return Attachment{ArtifactType: VEXArtifactType, MediaType: VEXDocumentMediaType, Name: name, Data: []byte(data)}
	}

	a, attached, err := Attach(ctx, store, manifest, doc("a", "document a"), nil)
	if err != nil || !attached {
		t.Fatalf("Attach(a) = %v, %v; want a new referrer", attached, err)
	}
	if _, attached, err := Attach(ctx, store, manifest, doc("b", "document b"), nil); err != nil || !attached {
		t.Fatalf("Attach(b) = %v, %v; want a new referrer", attached, err)
	}

	// The same document again, even under another name, attaches nothing
	// and reports the referrer already carrying it.
	again, attached, err := Attach(ctx, store, manifest, doc("renamed", "document a"), nil)
	if err != nil || attached || again.Digest != a.Digest {
		t.Fatalf("Attach(a again) = %s, %v, %v; want %s, not attached", again.Digest, attached, err, a.Digest)
	}

	referrers, err := Referrers(ctx, store, manifest, VEXArtifactType)
	if err != nil || len(referrers) != 2 {
		t.Fatalf("Referrers = %v, %v; want 2", referrers, err)
	}
	data, err := FetchAttachment(ctx, store, a, VEXDocumentMediaType)
	if err != nil || string(data) != "document a" {
		t.Errorf("FetchAttachment = %q, %v; want document a", data, err)
	}
	if _, err := FetchAttachment(ctx, store, a, "application/other"); err == nil {
		t.Error("FetchAttachment of the wrong media type: error = nil, want one")
	}
}

// TestReferrersOrder covers Referrers' newest-first order, by created
// annotation, and that other artifact types aren't listed.
func TestReferrersOrder(t *testing.T) {
	ctx := context.Background()
	store, manifest := newPackage(t)

	push := func(artifactType, created string) ocispec.Descriptor {
		t.Helper()
		layer, err := PushBytes(ctx, store, []byte(artifactType+created), "application/x-test", "layer", nil)
		if err != nil {
			t.Fatalf("push layer: %v", err)
		}
		r, err := PushReferrer(ctx, store, manifest, artifactType, []ocispec.Descriptor{layer},
			map[string]string{ocispec.AnnotationCreated: created}, "test")
		if err != nil {
			t.Fatalf("PushReferrer: %v", err)
		}
		return r
	}
	older := push("application/x-a", "2026-01-01T00:00:00Z")
	newer := push("application/x-a", "2026-02-01T00:00:00Z")
	push("application/x-b", "2026-03-01T00:00:00Z")

	got, err := Referrers(ctx, store, manifest, "application/x-a")
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(got) != 2 || got[0].Digest != newer.Digest || got[1].Digest != older.Digest {
		t.Errorf("Referrers = %v, want [newer older]", got)
	}
}
