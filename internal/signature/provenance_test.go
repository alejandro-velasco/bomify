package signature

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
)

// TestProvenanceVerifierRequiresSHA256 checks that a package whose
// manifest or SBOM isn't named by SHA-256, as provenance names them, is
// refused with an error saying so.
func TestProvenanceVerifierRequiresSHA256(t *testing.T) {
	ctx := context.Background()
	const ref = "registry.example.com/app:v1"
	verify := NewProvenanceVerifier(t.TempDir(), Policy{Verifier: Plugin{Kind: fakeKind}, Provenance: true}, discardLogger())
	store := memory.New()

	// push stores a package manifest whose config, the SBOM, has digest
	// config, and returns its descriptor.
	push := func(config digest.Digest) ocispec.Descriptor {
		t.Helper()
		data, err := json.Marshal(ocispec.Manifest{
			MediaType: ocispec.MediaTypeImageManifest,
			Config:    ocispec.Descriptor{MediaType: "application/vnd.cyclonedx+json", Digest: config, Size: 1},
			Layers:    []ocispec.Descriptor{},
		})
		if err != nil {
			t.Fatal(err)
		}
		desc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, data)
		if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		return desc
	}

	sha512Manifest := push(digest.Digest("sha256:" + strings.Repeat("5", 64)))
	sha512Manifest.Digest = digest.Digest("sha512:" + strings.Repeat("a", 128))
	if err := verify(ctx, store, ref, sha512Manifest); err == nil || !strings.Contains(err.Error(), "isn't SHA-256") {
		t.Errorf("SHA-512 manifest: %v, want an error that it isn't SHA-256", err)
	}

	sha512SBOM := push(digest.Digest("sha512:" + strings.Repeat("5", 128)))
	if err := verify(ctx, store, ref, sha512SBOM); err == nil || !strings.Contains(err.Error(), "isn't SHA-256") {
		t.Errorf("SHA-512 SBOM: %v, want an error that it isn't SHA-256", err)
	}

	noSBOM := push("")
	if err := verify(ctx, store, ref, noSBOM); err == nil || !strings.Contains(err.Error(), "isn't SHA-256") {
		t.Errorf("manifest with no SBOM digest: %v, want an error that it isn't SHA-256", err)
	}
}
