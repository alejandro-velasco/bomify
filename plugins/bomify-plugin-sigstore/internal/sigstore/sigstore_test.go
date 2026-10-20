package sigstore

import (
	"context"
	"crypto/elliptic"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
)

// githubIssuer is GitHub Actions' OIDC issuer, used here only as a
// realistic keyless option value.
const githubIssuer = "https://token.actions.githubusercontent.com"

var payload = []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":123}`)

// writeKeyPair generates an ECDSA P-256 key pair — encrypted with
// password in Sigstore's "ENCRYPTED SIGSTORE PRIVATE KEY" format when
// password is non-empty — and returns the private and public key paths.
func writeKeyPair(t *testing.T, password string) (privPath, pubPath string) {
	t.Helper()

	var pf cryptoutils.PassFunc
	if password != "" {
		pf = cryptoutils.StaticPasswordFunc([]byte(password))
	}
	privPEM, pubPEM, err := cryptoutils.GeneratePEMEncodedECDSAKeyPair(elliptic.P256(), pf)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	dir := t.TempDir()
	privPath, pubPath = filepath.Join(dir, "signing.key"), filepath.Join(dir, "signing.pub")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}

func TestKeySignThenVerify(t *testing.T) {
	priv, pub := writeKeyPair(t, "")

	envelope, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.Contains(string(envelope), "application/vnd.dev.sigstore.bundle.v0.3+json") {
		t.Errorf("envelope isn't a v0.3 bundle:\n%s", envelope)
	}

	signer, err := Verify(payload, envelope, Options{OptionKey: pub})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !strings.HasPrefix(signer, "key sha256:") {
		t.Errorf("signer = %q, want a key fingerprint", signer)
	}
}

func TestEncryptedKey(t *testing.T) {
	priv, pub := writeKeyPair(t, "hunter2")

	t.Setenv(passwordEnv, "wrong")
	if _, err := Sign(context.Background(), payload, Options{OptionKey: priv}); err == nil {
		t.Fatalf("Sign with the wrong %s: nil, want error", passwordEnv)
	}

	t.Setenv(passwordEnv, "hunter2")
	envelope, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(payload, envelope, Options{OptionKey: pub}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyWrongKeyFails(t *testing.T) {
	priv, _ := writeKeyPair(t, "")
	_, otherPub := writeKeyPair(t, "")

	envelope, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(payload, envelope, Options{OptionKey: otherPub}); err == nil {
		t.Fatal("Verify with a different public key: nil, want error")
	}
}

// TestVerifyOtherManifestFails covers what a signature pins: the
// manifest's digest, so it's no signature of any other manifest.
func TestVerifyOtherManifestFails(t *testing.T) {
	priv, pub := writeKeyPair(t, "")

	envelope, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	other := []byte(strings.Replace(string(payload), "sha256:0000", "sha256:1111", 1))
	if _, err := Verify(other, envelope, Options{OptionKey: pub}); err == nil {
		t.Fatal("Verify of another manifest: nil, want error")
	}
}

// TestSignWritesCosignsStatement pins the signature to what cosign 3
// signs, and so verifies: a DSSE envelope of an in-toto statement of
// cosign's sign predicate type, an empty predicate, and the manifest's
// digest as its one subject.
func TestSignWritesCosignsStatement(t *testing.T) {
	priv, _ := writeKeyPair(t, "")

	envelope, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(envelope); err != nil {
		t.Fatal(err)
	}
	dsse, err := b.Envelope()
	if err != nil {
		t.Fatalf("bundle holds no DSSE envelope: %v", err)
	}
	if dsse.PayloadType != pluginlib.InTotoPayloadType {
		t.Errorf("payload type = %q, want %q", dsse.PayloadType, pluginlib.InTotoPayloadType)
	}
	signed, err := dsse.DecodeB64Payload()
	if err != nil {
		t.Fatal(err)
	}
	var statement intoto.Statement
	if err := protojson.Unmarshal(signed, &statement); err != nil {
		t.Fatalf("parse statement %s: %v", signed, err)
	}
	subjects := statement.GetSubject()
	wantDigest := map[string]string{"sha256": strings.Repeat("0", 64)}
	if statement.GetType() != intoto.StatementTypeUri || statement.GetPredicateType() != SignPredicateType || len(statement.GetPredicate().GetFields()) != 0 {
		t.Errorf("statement = %s, want cosign's signature statement", signed)
	}
	if len(subjects) != 1 || subjects[0].GetName() != "" || !maps.Equal(subjects[0].GetDigest(), wantDigest) {
		t.Errorf("subjects = %v, want just the manifest's digest, %v", subjects, wantDigest)
	}

	annotations := SignatureAnnotations()
	if annotations["dev.sigstore.bundle.content"] != "dsse-envelope" || annotations["dev.sigstore.bundle.predicateType"] != SignPredicateType {
		t.Errorf("annotations = %v, want cosign's for a signature", annotations)
	}
}

// TestVerifyRefusesOtherAttestations covers telling a signature from any
// other attestation the same signer made of the manifest, such as a
// provenance `cosign attest` attached: only a signature verifies.
func TestVerifyRefusesOtherAttestations(t *testing.T) {
	priv, pub := writeKeyPair(t, "")
	provenance := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)

	envelope, err := Attest(context.Background(), provenance, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if _, err := Verify(payload, envelope, Options{OptionKey: pub}); err == nil || !strings.Contains(err.Error(), "predicate type") {
		t.Fatalf("Verify of a provenance attestation = %v, want it refused as no signature", err)
	}
}

// TestVerifyRefusesMessageSignatures covers signatures this plugin made
// before it signed as cosign does: a message signature of the payload,
// which cosign never verified, isn't verified either.
func TestVerifyRefusesMessageSignatures(t *testing.T) {
	priv, pub := writeKeyPair(t, "")

	envelope, err := signBundle(context.Background(), &sign.PlainData{Data: payload}, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Verify(payload, envelope, Options{OptionKey: pub}); err == nil {
		t.Fatal("Verify of a message signature: nil, want error")
	}
}

func TestSignRefusesAPayloadWithoutADigest(t *testing.T) {
	priv, _ := writeKeyPair(t, "")
	for name, bad := range map[string]string{
		"not JSON":     "not json",
		"no digest":    `{"mediaType":"application/vnd.oci.image.manifest.v1+json","size":123}`,
		"a bad digest": `{"digest":"sha256:xyz","size":123}`,
		"an empty one": `{}`,
	} {
		if _, err := Sign(context.Background(), []byte(bad), Options{OptionKey: priv}); err == nil {
			t.Errorf("%s: Sign = nil, want error", name)
		}
	}
}

func TestVerifyMalformedEnvelopeFails(t *testing.T) {
	_, pub := writeKeyPair(t, "")
	if _, err := Verify(payload, []byte("not a bundle"), Options{OptionKey: pub}); err == nil {
		t.Fatal("Verify of a malformed envelope: nil, want error")
	}
}

func TestKeylessSignNeedsToken(t *testing.T) {
	t.Setenv(idTokenEnv, "")

	_, err := Sign(context.Background(), payload, Options{})
	if err == nil || !strings.Contains(err.Error(), idTokenEnv) {
		t.Fatalf("Sign without a key or token: %v, want an error naming %s", err, idTokenEnv)
	}
}

func TestKeylessVerifyNeedsIdentity(t *testing.T) {
	priv, _ := writeKeyPair(t, "")
	envelope, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, opts := range []Options{
		{},
		{OptionCertificateIdentity: "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main"},
		{OptionCertificateOIDCIssuer: githubIssuer},
	} {
		if _, err := Verify(payload, envelope, opts); err == nil || !strings.Contains(err.Error(), "certificate identity") {
			t.Errorf("Verify(%v) = %v, want an error requiring both identity and issuer", opts, err)
		}
	}
}

func TestParseOptions(t *testing.T) {
	for _, good := range [][]string{
		nil,           // keyless signing: everything optional
		{"key=a.pub"}, // key-based
		{"certificate-identity=https://github.com/o/r/.github/workflows/release.yml@refs/heads/main", "certificate-oidc-issuer=" + githubIssuer},
		{"certificate-identity-regexp=^https://github.com/o/", "certificate-oidc-issuer-regexp=^https://token"},
		{"identity-token=abc"},
	} {
		if _, err := ParseOptions(good); err != nil {
			t.Errorf("ParseOptions(%q): %v", good, err)
		}
	}

	opts, err := ParseOptions([]string{"key=a.pub"})
	if err != nil || opts[OptionKey] != "a.pub" {
		t.Errorf("ParseOptions = %v, %v", opts, err)
	}

	for _, bad := range [][]string{
		{"key="},       // empty value
		{"novalue"},    // not key=value
		{"=a"},         // empty key
		{"kye=a.pub"},  // typo
		{"identity=x"}, // unknown option
		{"key=a.pub", "certificate-oidc-issuer=" + githubIssuer}, // key and keyless mixed
	} {
		if _, err := ParseOptions(bad); err == nil {
			t.Errorf("ParseOptions(%q): nil, want error", bad)
		}
	}
}

func TestIdentityTokenPrecedence(t *testing.T) {
	t.Setenv(idTokenEnv, "")
	if token := (Options{}).identityToken(); token != "" {
		t.Errorf("identityToken() = %q, want none", token)
	}

	t.Setenv(idTokenEnv, "env-token")
	if token := (Options{}).identityToken(); token != "env-token" {
		t.Errorf("identityToken() = %q, want %s's", token, idTokenEnv)
	}
	if token := (Options{OptionIdentityToken: "option-token"}).identityToken(); token != "option-token" {
		t.Errorf("identityToken() = %q, want the option to win", token)
	}
}

// TestKeyAttest covers signing an in-toto statement as an attestation:
// the bundle holds a DSSE envelope over the statement rather than a plain
// signature, and the annotations Sigstore's tools look for name it.
func TestKeyAttest(t *testing.T) {
	priv, _ := writeKeyPair(t, "")
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"app","digest":{"sha256":"ab"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)

	envelope, err := Attest(context.Background(), statement, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(envelope); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	dsse := b.GetDsseEnvelope()
	if dsse == nil {
		t.Fatalf("bundle has no DSSE envelope:\n%s", envelope)
	}
	if dsse.GetPayloadType() != pluginlib.InTotoPayloadType || string(dsse.GetPayload()) != string(statement) {
		t.Errorf("DSSE payload = %q (%s), want the statement as %s", dsse.GetPayload(), dsse.GetPayloadType(), pluginlib.InTotoPayloadType)
	}
	if len(dsse.GetSignatures()) == 0 {
		t.Error("DSSE envelope has no signatures")
	}

	annotations := AttestationAnnotations(statement)
	if annotations["dev.sigstore.bundle.content"] != "dsse-envelope" || annotations["dev.sigstore.bundle.predicateType"] != "https://slsa.dev/provenance/v1" {
		t.Errorf("annotations = %v", annotations)
	}
}

// TestKeyVerifyAttestation covers verifying an attestation: it returns
// the statement only for the trusted key and a subject it names.
func TestKeyVerifyAttestation(t *testing.T) {
	priv, pub := writeKeyPair(t, "")
	_, otherPub := writeKeyPair(t, "")
	digest := strings.Repeat("ab", 32)
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"app","digest":{"sha256":"` + digest + `"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)

	envelope, err := Attest(context.Background(), statement, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	signer, got, err := VerifyAttestation(envelope, "sha256:"+digest, Options{OptionKey: pub})
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if string(got) != string(statement) || !strings.HasPrefix(signer, "key sha256:") {
		t.Errorf("VerifyAttestation = %q, %s; want the key and the statement", signer, got)
	}

	if _, _, err := VerifyAttestation(envelope, "sha256:"+strings.Repeat("cd", 32), Options{OptionKey: pub}); err == nil {
		t.Error("VerifyAttestation of another subject: nil, want error")
	}
	if _, _, err := VerifyAttestation(envelope, "sha256:"+digest, Options{OptionKey: otherPub}); err == nil {
		t.Error("VerifyAttestation with an untrusted key: nil, want error")
	}

	// A plain signature isn't an attestation.
	plain, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := VerifyAttestation(plain, "sha256:"+digest, Options{OptionKey: pub}); err == nil {
		t.Error("VerifyAttestation of a plain signature: nil, want error")
	}
}
