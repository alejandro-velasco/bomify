package sign

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// pushPackage packs a bomify-package-shaped manifest into store, tagged
// ref, with a vulnerability report, a VEX document, and an unrelated
// referrer attached, and returns the manifest and the referrers Sign
// should sign.
func pushPackage(t *testing.T, store *oci.Store, ref string) (ocispec.Descriptor, []ocispec.Descriptor) {
	t.Helper()
	ctx := context.Background()

	config, err := transfer.PushBytes(ctx, store, []byte(`{"bomFormat":"CycloneDX"}`), "application/vnd.cyclonedx+json", "config", nil)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := transfer.PushBytes(ctx, store, []byte("layer"), transfer.LayerMediaType, "layer", nil)
	if err != nil {
		t.Fatal(err)
	}
	options := oras.PackManifestOptions{
		ConfigDescriptor: &config,
		Layers:           []ocispec.Descriptor{layer},
	}
	manifest, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, transfer.ArtifactType, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, manifest, ref); err != nil {
		t.Fatal(err)
	}

	attach := func(artifactType, body string) ocispec.Descriptor {
		t.Helper()
		blob, err := transfer.PushBytes(ctx, store, []byte(body), "application/json", body, nil)
		if err != nil {
			t.Fatal(err)
		}
		referrer, err := transfer.PushReferrer(ctx, store, manifest, artifactType, []ocispec.Descriptor{blob}, nil, body)
		if err != nil {
			t.Fatal(err)
		}
		return referrer
	}
	report := attach(transfer.VulnerabilityReportsArtifactType, `{"report":1}`)
	vex := attach(transfer.VEXArtifactType, `{"vex":1}`)
	attach("application/vnd.example.other", `{"other":1}`)
	return manifest, []ocispec.Descriptor{report, vex}
}

func newStore(t *testing.T) *oci.Store {
	t.Helper()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// recordingSigner is a transfer.Signer that records what it signs.
type recordingSigner struct {
	signed []ocispec.Descriptor
	err    error
}

func (r *recordingSigner) sign(_ context.Context, _ oras.Target, _ string, desc ocispec.Descriptor) error {
	r.signed = append(r.signed, desc)
	return r.err
}

func digests(descs []ocispec.Descriptor) []string {
	var out []string
	for _, desc := range descs {
		out = append(out, desc.Digest.String())
	}
	slices.Sort(out)
	return out
}

func TestSignSignsPackageAndItsReferrers(t *testing.T) {
	store := newStore(t)
	manifest, referrers := pushPackage(t, store, "app:1.0")
	signer := &recordingSigner{}

	result, err := Sign(context.Background(), store, "app:1.0", signer.sign)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if result.Manifest.Digest != manifest.Digest || signer.signed[0].Digest != manifest.Digest {
		t.Errorf("signed first %v, result manifest %v; want the package manifest %v", signer.signed[0].Digest, result.Manifest.Digest, manifest.Digest)
	}
	want := digests(referrers)
	if got := digests(result.Referrers); !slices.Equal(got, want) {
		t.Errorf("signed referrers %v, want the report and VEX %v", got, want)
	}
	if len(signer.signed) != 3 {
		t.Errorf("signed %d descriptors, want 3: the package, its report, and its VEX, not the unrelated referrer", len(signer.signed))
	}
}

func TestSignRejects(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	pushPackage(t, store, "app:1.0")

	other, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "application/vnd.example.image", oras.PackManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, other, "other:1.0"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, ref string
		signErr   error
		want      string
	}{
		{"missing tag", "nope:1.0", nil, "resolve nope:1.0"},
		{"not a bomify package", "other:1.0", nil, "isn't a bomify package"},
		{"signer fails", "app:1.0", errors.New("no key"), "no key"},
	} {
		signer := &recordingSigner{err: tc.signErr}
		_, err := Sign(ctx, store, tc.ref, signer.sign)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Sign = %v, want an error containing %q", tc.name, err, tc.want)
		}
		if tc.name == "not a bomify package" && len(signer.signed) != 0 {
			t.Errorf("%s: signed %d descriptors, want none", tc.name, len(signer.signed))
		}
	}
}

func TestSignArchive(t *testing.T) {
	ctx := context.Background()
	stageDir := t.TempDir()
	store, err := oci.New(stageDir)
	if err != nil {
		t.Fatal(err)
	}
	pushPackage(t, store, "app:1.0")
	pushPackage(t, store, "app:2.0")
	var archive bytes.Buffer
	if err := transfer.WriteTar(stageDir, &archive); err != nil {
		t.Fatal(err)
	}

	signer := &recordingSigner{}
	var signed bytes.Buffer
	results, err := SignArchive(ctx, &archive, &signed, signer.sign)
	if err != nil {
		t.Fatalf("SignArchive: %v", err)
	}

	var tags []string
	for _, result := range results {
		tags = append(tags, result.Tag)
	}
	slices.Sort(tags)
	if !slices.Equal(tags, []string{"app:1.0", "app:2.0"}) || len(signer.signed) != 6 {
		t.Errorf("signed tags %v with %d signatures, want both tags, 3 each", tags, len(signer.signed))
	}
	if signed.Len() == 0 {
		t.Error("SignArchive wrote no tarball")
	}

	if _, err := SignArchive(ctx, strings.NewReader("not a tarball"), &bytes.Buffer{}, signer.sign); err == nil {
		t.Error("SignArchive of a non-tarball: nil, want error")
	}
}
