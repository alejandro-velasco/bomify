package provenance

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// statement is an in-toto SLSA provenance statement as it's encoded, so
// tests check the JSON other tools read rather than round-tripping the
// protobuf types.
type statement struct {
	Type          string     `json:"_type"`
	Subject       []resource `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     struct {
		BuildDefinition struct {
			BuildType          string `json:"buildType"`
			ExternalParameters struct {
				SBOM resource `json:"sbom"`
				Tags []string `json:"tags"`
			} `json:"externalParameters"`
			ResolvedDependencies []resource `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata struct {
				StartedOn string `json:"startedOn"`
			} `json:"metadata"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

type resource struct {
	URI    string            `json:"uri,omitempty"`
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// decode parses data as a statement.
func decode(t *testing.T, data []byte) statement {
	t.Helper()
	var s statement
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse statement: %v\n%s", err, data)
	}
	return s
}

// Digests the tests record: in-toto validates a sha256 as 64 hex digits.
var (
	sbomHash   = strings.Repeat("5", 64)
	subjectSum = strings.Repeat("c", 64)
	nginxSum   = strings.Repeat("a", 64)
	ociSum     = strings.Repeat("b", 64)
	genericSum = strings.Repeat("f", 64)
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
	r.AddComponent("pkg:oci/nginx@1.27", strings.ToUpper(nginxSum))
	r.AddComponent("pkg:generic/nohash@1.0", "")
	if err := r.AddPlugin("oci", "unused", "v1.2.0", ociSum, fakeHash(ociSum)); err != nil {
		t.Fatal(err)
	}
	// Recorded once per kind, however many components use it.
	if err := r.AddPlugin("oci", "unused", "v1.2.0", ociSum, fakeHash(strings.Repeat("e", 64))); err != nil {
		t.Fatal(err)
	}
	// A binary that no longer matches its install record isn't credited
	// with that record's version.
	if err := r.AddPlugin("generic", "unused", "v9.9.9", strings.Repeat("d", 64), fakeHash(genericSum)); err != nil {
		t.Fatal(err)
	}
	if err := r.Write(dir, sbomHash, []string{"app:1.0"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return dir
}

func TestRecorder(t *testing.T) {
	dir := record(t, sbomHash)

	p, ok, err := Read(dir, sbomHash)
	if err != nil || !ok {
		t.Fatalf("Read = %v, %v; want the record", ok, err)
	}
	if _, ok, _ := Read(dir, "other"); ok {
		t.Error("Read of a build with no record: ok = true")
	}
	data, err := NewStatement(p, "app", subjectSum)
	if err != nil {
		t.Fatal(err)
	}
	s := decode(t, data)

	b := s.Predicate.BuildDefinition
	if b.BuildType != BuildType || s.Predicate.RunDetails.Builder.ID != BuilderID {
		t.Errorf("buildType/builder = %q/%q", b.BuildType, s.Predicate.RunDetails.Builder.ID)
	}
	if b.ExternalParameters.SBOM.Digest["sha256"] != sbomHash || len(b.ExternalParameters.Tags) != 1 || b.ExternalParameters.Tags[0] != "app:1.0" {
		t.Errorf("externalParameters = %+v", b.ExternalParameters)
	}
	if _, err := time.Parse(time.RFC3339, s.Predicate.RunDetails.Metadata.StartedOn); err != nil {
		t.Errorf("startedOn: %v", err)
	}

	want := []resource{
		{URI: "pkg:bomify-plugin/generic", Name: "bomify-plugin-generic", Digest: map[string]string{"sha256": genericSum}},
		{URI: "pkg:bomify-plugin/oci@v1.2.0", Name: "bomify-plugin-oci", Digest: map[string]string{"sha256": ociSum}},
		{URI: "pkg:generic/nohash@1.0"},
		{URI: "pkg:oci/nginx@1.27", Digest: map[string]string{"sha256": nginxSum}},
	}
	gotJSON, _ := json.Marshal(b.ResolvedDependencies)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("resolvedDependencies =\n%s\nwant\n%s", gotJSON, wantJSON)
	}
}

func TestInvocationID(t *testing.T) {
	const run = "https://ci.example.com/jobs/42"
	t.Setenv(InvocationIDEnv, run)
	dir := record(t, sbomHash)
	p, _, err := Read(dir, sbomHash)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.GetRunDetails().GetMetadata().GetInvocationId(); got != run {
		t.Errorf("invocationId = %q, want %q", got, run)
	}
}

func TestNewStatement(t *testing.T) {
	p, _, _ := Read(record(t, sbomHash), sbomHash)
	a, err := NewStatement(p, "registry.example.com/app", subjectSum)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewStatement(p, "registry.example.com/app", subjectSum)
	if string(a) != string(b) {
		t.Error("NewStatement isn't deterministic")
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, a); err != nil || compact.String() != string(a) {
		t.Errorf("NewStatement isn't compact JSON (%v):\n%s", err, a)
	}

	s := decode(t, a)
	if s.Type != "https://in-toto.io/Statement/v1" || s.PredicateType != PredicateType || s.Subject[0].Name != "registry.example.com/app" || s.Subject[0].Digest["sha256"] != subjectSum {
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
	dir := record(t, sbomHash)
	store, manifest := packageStore(t)

	referrer, attached, err := Attach(ctx, store, "registry.example.com/app:1.0", dir, sbomHash, manifest, nil)
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
	s := decode(t, data)
	if s.Subject[0].Name != "registry.example.com/app" || s.Subject[0].Digest["sha256"] != manifest.Digest.Encoded() {
		t.Errorf("subject = %+v, want the package manifest", s.Subject)
	}

	// Pushing the same provenance again attaches nothing new.
	again, attached, err := Attach(ctx, store, "registry.example.com/app:1.0", dir, sbomHash, manifest, nil)
	if err != nil || attached || again.Digest != referrer.Digest {
		t.Errorf("Attach again = %s, %v, %v; want the existing referrer", again.Digest, attached, err)
	}

	// A build that recorded no provenance attaches none.
	if _, attached, err := Attach(ctx, store, "app:1.0", t.TempDir(), sbomHash, manifest, nil); err != nil || attached {
		t.Errorf("Attach without a record = %v, %v; want nothing attached", attached, err)
	}
}

func TestAttachSigned(t *testing.T) {
	ctx := context.Background()
	dir := record(t, sbomHash)
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

	if _, attached, err := Attach(ctx, store, "app:1.0", dir, sbomHash, manifest, attest); err != nil || !attached {
		t.Fatalf("Attach = %v, %v; want attached", attached, err)
	}
	if _, attached, err := Attach(ctx, store, "app:1.0", dir, sbomHash, manifest, attest); err != nil || attached {
		t.Fatalf("Attach again = %v, %v; want nothing new", attached, err)
	}
	if calls != 1 {
		t.Errorf("attester called %d times, want 1", calls)
	}
}

func TestWriteReplacesRecord(t *testing.T) {
	dir := record(t, sbomHash)
	r := NewRecorder()
	if err := r.Write(dir, sbomHash, nil); err != nil {
		t.Fatal(err)
	}
	p, _, _ := Read(dir, sbomHash)
	if deps := p.GetBuildDefinition().GetResolvedDependencies(); len(deps) != 0 {
		t.Errorf("record not replaced: %v", deps)
	}
	if _, err := os.Stat(filepath.Join(dir, "provenance", sbomHash+".json")); err != nil {
		t.Errorf("record not at provenance/<hash>.json: %v", err)
	}
}
