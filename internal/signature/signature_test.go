package signature

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// fakeKind is the plugin kind the fake signing plugin (see testutil)
// is installed as.
const fakeKind = "fakesign"

// pluginDir is the plugins directory installFakeSigner installed the fake
// signer into, for NewSigner/NewVerifier/Verify to find it in.
var pluginDir string

// installFakeSigner installs the fake plugin (see testutil) as
// bomify-plugin-fakesign into a fresh plugins directory and points
// pluginDir at it.
func installFakeSigner(t *testing.T) {
	t.Helper()
	pluginDir = t.TempDir()
	testutil.InstallFakePlugin(t, pluginDir, fakeKind)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// pushPackage packs a minimal bomify-package-shaped manifest (config +
// one layer, whose content is distinguished by name) into store, tagged
// ref, and returns its descriptor.
func pushPackage(t *testing.T, store *oci.Store, ref, name string) ocispec.Descriptor {
	t.Helper()
	ctx := context.Background()

	config, err := transfer.PushBytes(ctx, store, []byte(`{"bomFormat":"CycloneDX","name":"`+name+`"}`), "application/vnd.cyclonedx+json", "config", nil)
	if err != nil {
		t.Fatalf("push config: %v", err)
	}
	layer, err := transfer.PushBytes(ctx, store, []byte("layer "+name), transfer.LayerMediaType, "layer", nil)
	if err != nil {
		t.Fatalf("push layer: %v", err)
	}

	desc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, transfer.ArtifactType, oras.PackManifestOptions{
		ConfigDescriptor: &config,
		Layers:           []ocispec.Descriptor{layer},
	})
	if err != nil {
		t.Fatalf("pack manifest: %v", err)
	}
	if err := store.Tag(ctx, desc, ref); err != nil {
		t.Fatalf("tag: %v", err)
	}
	return desc
}

func newStore(t *testing.T) *oci.Store {
	t.Helper()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("oci.New: %v", err)
	}
	return store
}

func sign(t *testing.T, store *oci.Store, ref string, manifest ocispec.Descriptor, key string) {
	t.Helper()
	signer, err := NewSigner(pluginDir, Plugin{Kind: fakeKind, Options: []string{"key=" + key}}, discardLogger())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if err := signer(context.Background(), store, ref, manifest); err != nil {
		t.Fatalf("sign: %v", err)
	}
}

func verify(store *oci.Store, ref string, manifest ocispec.Descriptor, key string) (string, error) {
	return VerifySignature(context.Background(), store, ref, manifest, pluginDir, Plugin{Kind: fakeKind, Options: []string{"key=" + key}}, discardLogger())
}

func TestSignThenVerify(t *testing.T) {
	installFakeSigner(t)
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	sign(t, store, "app:v1", manifest, "secret")

	signer, err := verify(store, "app:v1", manifest, "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if signer != "key:secret" {
		t.Errorf("signer = %q, want %q", signer, "key:secret")
	}
}

func TestSignAttachesReferrer(t *testing.T) {
	installFakeSigner(t)
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	sign(t, store, "app:v1", manifest, "secret")

	referrers, err := registry.Referrers(context.Background(), store, manifest, "")
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(referrers) != 1 {
		t.Fatalf("got %d referrers, want 1", len(referrers))
	}
	if got := referrers[0].ArtifactType; got != "application/vnd.bomify.test.signature" {
		t.Errorf("referrer artifactType = %q, want the plugin's own", got)
	}
	if got := referrers[0].Annotations[AnnotationPlugin]; got != fakeKind {
		t.Errorf("referrer %s annotation = %q, want %q", AnnotationPlugin, got, fakeKind)
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	installFakeSigner(t)
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	sign(t, store, "app:v1", manifest, "secret")

	_, err := verify(store, "app:v1", manifest, "other")
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("Verify error = %v, want the plugin's verification failure", err)
	}
}

func TestVerifyUnsignedFails(t *testing.T) {
	installFakeSigner(t)
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	_, err := verify(store, "app:v1", manifest, "secret")
	if err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("Verify error = %v, want a no-signature error", err)
	}
}

func TestVerifyIgnoresUnsupportedArtifactTypes(t *testing.T) {
	installFakeSigner(t)
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	sign(t, store, "app:v1", manifest, "secret")
	t.Setenv("FAKESIGN_TYPES", "application/vnd.example.other")

	_, err := verify(store, "app:v1", manifest, "secret")
	if err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("Verify error = %v, want a no-signature error when no referrer is of a supported type", err)
	}
}

func TestVerifyAnyOfSeveralSignatures(t *testing.T) {
	installFakeSigner(t)
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	sign(t, store, "app:v1", manifest, "alice")
	sign(t, store, "app:v1", manifest, "bob")

	signer, err := verify(store, "app:v1", manifest, "bob")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if signer != "key:bob" {
		t.Errorf("signer = %q, want %q", signer, "key:bob")
	}
}

// TestVerifyRejectsReplayedEnvelope proves a signature is bound to the
// manifest it was made over, not merely to whichever manifest its
// referrer happens to name as subject: an envelope lifted from one
// package's signature and re-attached to a different package must fail.
func TestVerifyRejectsReplayedEnvelope(t *testing.T) {
	installFakeSigner(t)
	ctx := context.Background()
	store := newStore(t)
	genuine := pushPackage(t, store, "app:v1", "genuine")
	forged := pushPackage(t, store, "app:v2", "forged")

	sign(t, store, "app:v1", genuine, "secret")

	referrers, err := registry.Referrers(ctx, store, genuine, "")
	if err != nil || len(referrers) != 1 {
		t.Fatalf("Referrers = %v, %v; want exactly 1", referrers, err)
	}
	data, err := content.FetchAll(ctx, store, referrers[0])
	if err != nil {
		t.Fatalf("fetch referrer: %v", err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse referrer: %v", err)
	}

	subject := ocispec.Descriptor{MediaType: forged.MediaType, Digest: forged.Digest, Size: forged.Size}
	if _, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, referrers[0].ArtifactType, oras.PackManifestOptions{
		Subject: &subject,
		Layers:  m.Layers,
	}); err != nil {
		t.Fatalf("attach replayed envelope: %v", err)
	}

	if _, err := verify(store, "app:v2", forged, "secret"); err == nil {
		t.Fatal("Verify succeeded for a signature made over a different manifest")
	}
}

func TestNewSignerMissingPlugin(t *testing.T) {
	if _, err := NewSigner(t.TempDir(), Plugin{Kind: "nope"}, discardLogger()); err == nil {
		t.Fatal("NewSigner error = nil, want error for a plugin that isn't installed")
	}
}

func TestNewVerifierAppliesPolicy(t *testing.T) {
	installFakeSigner(t)
	ctx := context.Background()
	store := newStore(t)
	signed := pushPackage(t, store, "registry.example.com/team/app:v1", "signed")
	unsigned := pushPackage(t, store, "registry.example.com/other/app:v1", "unsigned")
	sign(t, store, "registry.example.com/team/app:v1", signed, "secret")

	policy := Policy{Rules: Config{{Match: "registry.example.com/team", Signers: one(fakeKind, "key=secret")}}}
	verifier := NewVerifier(pluginDir, policy, discardLogger())

	if err := verifier(ctx, store, "registry.example.com/team/app:v1", signed); err != nil {
		t.Errorf("signed package matching a rule: %v", err)
	}
	if err := verifier(ctx, store, "registry.example.com/other/app:v1", unsigned); err != nil {
		t.Errorf("unsigned package matching no rule: %v, want nil", err)
	}

	policy.Rules[0].Match = ""
	verifier = NewVerifier(pluginDir, policy, discardLogger())
	if err := verifier(ctx, store, "registry.example.com/other/app:v1", unsigned); err == nil {
		t.Error("unsigned package matching a catch-all rule: nil, want error")
	}

	policy.Skip = true
	verifier = NewVerifier(pluginDir, policy, discardLogger())
	if err := verifier(ctx, store, "registry.example.com/other/app:v1", unsigned); err != nil {
		t.Errorf("unsigned package with Skip: %v, want nil", err)
	}
}

// signers are a rule's signers, one per key, each verified with the
// fake plugin.
func signers(keys ...string) []Signer {
	s := make([]Signer, len(keys))
	for i, key := range keys {
		s[i] = Signer{Name: key, Kind: fakeKind, Options: []string{"key=" + key}}
	}
	return s
}

func TestVerifySigners(t *testing.T) {
	installFakeSigner(t)
	ctx := context.Background()
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")
	sign(t, store, "app:v1", manifest, "alice")
	sign(t, store, "app:v1", manifest, "bob")

	for _, tc := range []struct {
		name string
		req  Requirement
		want string // a substring of the error; "" for success
	}{
		{"all signed", Requirement{Signers: signers("alice", "bob")}, ""},
		{"one missing", Requirement{Signers: signers("alice", "bob", "carol")}, `2 of the 3 required signers verified: signer "carol"`},
		{"two of three", Requirement{Signers: signers("alice", "carol", "bob"), Require: 2}, ""},
		{"too few of three", Requirement{Signers: signers("alice", "carol", "dave"), Require: 2}, "1 of the 2 required"},
		{"one signer keeps its error", Requirement{Signers: signers("carol")}, "does not verify"},
	} {
		err := VerifySigners(ctx, store, "app:v1", manifest, pluginDir, tc.req, discardLogger())
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error = %v, want one containing %q", tc.name, err, tc.want)
		case tc.want != "" && len(tc.req.Signers) == 1 && strings.Contains(err.Error(), "required signers"):
			t.Errorf("%s: error = %v, want the single signer's error as is", tc.name, err)
		}
	}
}

func TestNewSignersSignsWithEach(t *testing.T) {
	installFakeSigner(t)
	ctx := context.Background()
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	sign, attest, err := NewSigners(pluginDir, []Plugin{
		{Kind: fakeKind, Options: []string{"key=alice"}},
		{Kind: fakeKind, Options: []string{"key=bob"}},
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewSigners: %v", err)
	}
	if err := sign(ctx, store, "app:v1", manifest); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifySigners(ctx, store, "app:v1", manifest, pluginDir, Requirement{Signers: signers("alice", "bob")}, discardLogger()); err != nil {
		t.Errorf("verify both signers: %v", err)
	}

	first, err := attest(ctx, store, "app:v1", manifest, []byte(`{}`), map[string]string{transfer.AnnotationAttestation: "https://example.com/predicate"})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	referrers, err := registry.Referrers(ctx, store, manifest, "")
	if err != nil {
		t.Fatal(err)
	}
	var attestations []ocispec.Descriptor
	for _, r := range referrers {
		if r.Annotations[transfer.AnnotationAttestation] != "" {
			attestations = append(attestations, r)
		}
	}
	if len(attestations) != 2 {
		t.Errorf("got %d attestations, want one per signer", len(attestations))
	}
	if first.Digest == "" {
		t.Error("attest returned no descriptor")
	}

	if _, _, err := NewSigners(pluginDir, []Plugin{{Kind: fakeKind}, {Kind: "nope"}}, discardLogger()); err == nil {
		t.Error("NewSigners with a missing plugin: nil, want error")
	}
}

func TestPayloadIgnoresArtifactType(t *testing.T) {
	store := newStore(t)
	desc := pushPackage(t, store, "app:v1", "app")

	withType := readPayload(t, desc)
	desc.ArtifactType = ""
	desc.Annotations = nil
	without := readPayload(t, desc)
	if withType != without {
		t.Errorf("payload differs by artifactType/annotations:\n%s\n%s", withType, without)
	}
}

// readPayload returns the payload writePayload writes for manifest.
func readPayload(t *testing.T, manifest ocispec.Descriptor) string {
	t.Helper()

	path, cleanup, err := writePayload(manifest)
	if err != nil {
		t.Fatalf("writePayload: %v", err)
	}
	defer cleanup()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return string(data)
}

// TestVerifySkipsAttestations covers an attestation signed with the same
// plugin, and so the same artifact type, as a package signature: even
// one whose statement is byte-for-byte the signing payload must never
// count as the package's signature.
func TestVerifySkipsAttestations(t *testing.T) {
	installFakeSigner(t)
	store := newStore(t)
	manifest := pushPackage(t, store, "app:v1", "app")

	payloadFile, cleanup, err := writePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	payload, err := os.ReadFile(payloadFile)
	if err != nil {
		t.Fatal(err)
	}

	attest, err := NewAttester(pluginDir, Plugin{Kind: fakeKind, Options: []string{"key=secret"}}, discardLogger())
	if err != nil {
		t.Fatalf("NewAttester: %v", err)
	}
	referrer, err := attest(context.Background(), store, "app:v1", manifest, payload, map[string]string{transfer.AnnotationAttestation: "https://example.com/predicate"})
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if referrer.ArtifactType == "" {
		t.Fatalf("attestation referrer = %+v", referrer)
	}

	if _, err := verify(store, "app:v1", manifest, "secret"); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("Verify error = %v, want the attestation ignored", err)
	}
}
