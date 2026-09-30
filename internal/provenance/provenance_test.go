package provenance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

func fakeHash(sum string) func(string) (string, error) {
	return func(string) (string, error) { return sum, nil }
}

// record writes a provenance record for sbomHash into a fresh data
// directory and returns it.
func record(t *testing.T, sbomHash string) string {
	t.Helper()
	dir := t.TempDir()
	r := NewRecorder()
	r.AddComponent("pkg:oci/nginx@1.27", "AAAA")
	r.AddComponent("pkg:generic/nohash@1.0", "")
	if err := r.AddPlugin("oci", "unused", "v1.2.0", "bbbb", fakeHash("bbbb")); err != nil {
		t.Fatal(err)
	}
	// Recorded once per kind, however many components use it.
	if err := r.AddPlugin("oci", "unused", "v1.2.0", "bbbb", fakeHash("different")); err != nil {
		t.Fatal(err)
	}
	// A binary that no longer matches its install record isn't credited
	// with that record's version.
	if err := r.AddPlugin("generic", "unused", "v9.9.9", "recorded", fakeHash("actual")); err != nil {
		t.Fatal(err)
	}
	if err := r.Write(dir, sbomHash, []string{"app:1.0"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir
}

func TestRecorder(t *testing.T) {
	dir := record(t, "5bom")

	p, ok, err := Read(dir, "5bom")
	if err != nil || !ok {
		t.Fatalf("Read = %v, %v; want the record", ok, err)
	}
	if _, ok, _ := Read(dir, "other"); ok {
		t.Error("Read of a build with no record: ok = true")
	}

	if p.BuildDefinition.BuildType != BuildType || p.RunDetails.Builder.ID != BuilderID {
		t.Errorf("buildType/builder = %q/%q", p.BuildDefinition.BuildType, p.RunDetails.Builder.ID)
	}
	if got := p.BuildDefinition.ExternalParameters.SBOM.Digest["sha256"]; got != "5bom" {
		t.Errorf("sbom digest = %q", got)
	}

	want := []ResourceDescriptor{
		{URI: "pkg:bomify-plugin/generic", Name: "bomify-plugin-generic", Digest: map[string]string{"sha256": "actual"}},
		{URI: "pkg:bomify-plugin/oci@v1.2.0", Name: "bomify-plugin-oci", Digest: map[string]string{"sha256": "bbbb"}},
		{URI: "pkg:generic/nohash@1.0"},
		{URI: "pkg:oci/nginx@1.27", Digest: map[string]string{"sha256": "aaaa"}},
	}
	gotJSON, _ := json.Marshal(p.BuildDefinition.ResolvedDependencies)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("resolvedDependencies =\n%s\nwant\n%s", gotJSON, wantJSON)
	}
}

func TestNewStatement(t *testing.T) {
	p, _, _ := Read(record(t, "5bom"), "5bom")
	a, err := NewStatement(p, "registry.example.com/app", "abc")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewStatement(p, "registry.example.com/app", "abc")
	if string(a) != string(b) {
		t.Error("NewStatement isn't deterministic")
	}

	var s Statement
	if err := json.Unmarshal(a, &s); err != nil {
		t.Fatal(err)
	}
	if s.Type != StatementType || s.PredicateType != PredicateType || s.Subject[0].Name != "registry.example.com/app" || s.Subject[0].Digest["sha256"] != "abc" {
		t.Errorf("statement = %+v", s)
	}
}

// packageStore returns an OCI layout holding one empty package manifest.
func packageStore(t *testing.T) (*oci.Store, ocispec.Descriptor) {
	t.Helper()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := oras.PackManifest(context.Background(), store, oras.PackManifestVersion1_1, transfer.ArtifactType, oras.PackManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return store, manifest
}

func TestAttachUnsigned(t *testing.T) {
	ctx := context.Background()
	dir := record(t, "5bom")
	store, manifest := packageStore(t)

	referrer, attached, err := Attach(ctx, store, "registry.example.com/app:1.0", dir, "5bom", manifest, nil)
	if err != nil || !attached {
		t.Fatalf("Attach = %v, %v; want attached", attached, err)
	}
	if referrer.ArtifactType != MediaType || referrer.Annotations[transfer.AnnotationAttestation] != PredicateType {
		t.Errorf("referrer = %+v", referrer)
	}

	layers, err := transfer.ReferrerLayers(ctx, store, referrer, MediaType)
	if err != nil || len(layers) != 1 {
		t.Fatalf("layers = %v, %v", layers, err)
	}
	data, err := content.FetchAll(ctx, store, layers[0])
	if err != nil {
		t.Fatal(err)
	}
	var s Statement
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if s.Subject[0].Name != "registry.example.com/app" || s.Subject[0].Digest["sha256"] != manifest.Digest.Encoded() {
		t.Errorf("subject = %+v, want the package manifest", s.Subject)
	}

	// Pushing the same provenance again attaches nothing new.
	again, attached, err := Attach(ctx, store, "registry.example.com/app:1.0", dir, "5bom", manifest, nil)
	if err != nil || attached || again.Digest != referrer.Digest {
		t.Errorf("Attach again = %s, %v, %v; want the existing referrer", again.Digest, attached, err)
	}

	// A build that recorded no provenance attaches none.
	if _, attached, err := Attach(ctx, store, "app:1.0", t.TempDir(), "5bom", manifest, nil); err != nil || attached {
		t.Errorf("Attach without a record = %v, %v; want nothing attached", attached, err)
	}
}

func TestAttachSigned(t *testing.T) {
	ctx := context.Background()
	dir := record(t, "5bom")
	store, manifest := packageStore(t)

	calls := 0
	attest := func(ctx context.Context, target oras.Target, ref string, subject ocispec.Descriptor, statement []byte, annotations map[string]string) (ocispec.Descriptor, error) {
		calls++
		layer, err := transfer.PushBytes(ctx, target, append([]byte("signed:"), statement...), "application/x-envelope", "envelope", nil)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		// A real signature is different every time, so dedup can't rely
		// on content.
		annotations = map[string]string{
			AnnotationStatement:            annotations[AnnotationStatement],
			transfer.AnnotationAttestation: annotations[transfer.AnnotationAttestation],
			"nonce":                        string(rune('0' + calls)),
		}
		return transfer.PushReferrer(ctx, target, subject, "application/x-bundle", []ocispec.Descriptor{layer}, annotations, "attestation")
	}

	if _, attached, err := Attach(ctx, store, "app:1.0", dir, "5bom", manifest, attest); err != nil || !attached {
		t.Fatalf("Attach = %v, %v; want attached", attached, err)
	}
	if _, attached, err := Attach(ctx, store, "app:1.0", dir, "5bom", manifest, attest); err != nil || attached {
		t.Fatalf("Attach again = %v, %v; want nothing new", attached, err)
	}
	if calls != 1 {
		t.Errorf("attester called %d times, want 1", calls)
	}
}

func TestWriteReplacesRecord(t *testing.T) {
	dir := record(t, "5bom")
	r := NewRecorder()
	if err := r.Write(dir, "5bom", nil); err != nil {
		t.Fatal(err)
	}
	p, _, _ := Read(dir, "5bom")
	if len(p.BuildDefinition.ResolvedDependencies) != 0 {
		t.Errorf("record not replaced: %+v", p.BuildDefinition.ResolvedDependencies)
	}
	if _, err := os.Stat(filepath.Join(dir, "provenance", "5bom.json")); err != nil {
		t.Errorf("record not at provenance/<hash>.json: %v", err)
	}
}
