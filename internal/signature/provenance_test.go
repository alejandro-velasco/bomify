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

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// TestProvenanceVerifierRequiresSHA256 checks that a package whose index
// or SBOM isn't named by SHA-256, as provenance names them, is refused
// with an error saying so.
func TestProvenanceVerifierRequiresSHA256(t *testing.T) {
	ctx := context.Background()
	const ref = "registry.example.com/app:v1"
	verify := NewProvenanceVerifier(t.TempDir(), Policy{Verifier: Plugin{Kind: fakeKind}, Provenance: true}, discardLogger())
	store := memory.New()

	// pushJSON stores v as a manifest of mediaType, returning its
	// descriptor.
	pushJSON := func(mediaType string, v any) ocispec.Descriptor {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		desc := content.NewDescriptorFromBytes(mediaType, data)
		if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		return desc
	}
	// push stores a package index whose SBOM manifest's config, the SBOM,
	// has digest config, and returns its descriptor.
	push := func(config digest.Digest) ocispec.Descriptor {
		t.Helper()
		sbomManifest := ocispec.Manifest{
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: transfer.SBOMArtifactType,
			Config:       ocispec.Descriptor{MediaType: "application/vnd.cyclonedx+json", Digest: config, Size: 1},
			Layers:       []ocispec.Descriptor{},
		}
		sbomDesc := pushJSON(ocispec.MediaTypeImageManifest, sbomManifest)
		sbomDesc.ArtifactType = transfer.SBOMArtifactType
		index := ocispec.Index{
			MediaType:    ocispec.MediaTypeImageIndex,
			ArtifactType: transfer.ArtifactType,
			Manifests:    []ocispec.Descriptor{sbomDesc},
		}
		return pushJSON(ocispec.MediaTypeImageIndex, index)
	}

	sha512Index := push(digest.Digest("sha256:" + strings.Repeat("5", 64)))
	sha512Index.Digest = digest.Digest("sha512:" + strings.Repeat("a", 128))
	if err := verify(ctx, store, ref, sha512Index); err == nil || !strings.Contains(err.Error(), "isn't SHA-256") {
		t.Errorf("SHA-512 index: %v, want an error that it isn't SHA-256", err)
	}

	sha512SBOM := push(digest.Digest("sha512:" + strings.Repeat("5", 128)))
	if err := verify(ctx, store, ref, sha512SBOM); err == nil || !strings.Contains(err.Error(), "isn't SHA-256") {
		t.Errorf("SHA-512 SBOM: %v, want an error that it isn't SHA-256", err)
	}

	noSBOM := push("")
	if err := verify(ctx, store, ref, noSBOM); err == nil || !strings.Contains(err.Error(), "isn't SHA-256") {
		t.Errorf("package with no SBOM digest: %v, want an error that it isn't SHA-256", err)
	}
}
