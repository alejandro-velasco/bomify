package sigstore

import (
	"context"
	"crypto/elliptic"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var payload = []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":123}`)

// writeKeyPair generates an ECDSA P-256 key pair — encrypted with
// password in cosign's own "ENCRYPTED SIGSTORE PRIVATE KEY" format when
// password is non-empty, exactly as `cosign generate-key-pair` writes
// it — and returns the private and public key paths.
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
	privPath, pubPath = filepath.Join(dir, "cosign.key"), filepath.Join(dir, "cosign.pub")
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

func TestEncryptedCosignKey(t *testing.T) {
	priv, pub := writeKeyPair(t, "hunter2")

	t.Setenv(passwordEnv, "wrong")
	if _, err := Sign(context.Background(), payload, Options{OptionKey: priv}); err == nil {
		t.Fatal("Sign with the wrong COSIGN_PASSWORD: nil, want error")
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

func TestVerifyTamperedPayloadFails(t *testing.T) {
	priv, pub := writeKeyPair(t, "")

	envelope, err := Sign(context.Background(), payload, Options{OptionKey: priv})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := []byte(strings.Replace(string(payload), `"size":123`, `"size":124`, 1))
	if _, err := Verify(tampered, envelope, Options{OptionKey: pub}); err == nil {
		t.Fatal("Verify of a different payload: nil, want error")
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
		{OptionCertificateIdentity: "release@example.com"},
		{OptionCertificateOIDCIssuer: "https://accounts.google.com"},
	} {
		if _, err := Verify(payload, envelope, opts); err == nil || !strings.Contains(err.Error(), "certificate identity") {
			t.Errorf("Verify(%v) = %v, want an error requiring both identity and issuer", opts, err)
		}
	}
}

func TestParseOptions(t *testing.T) {
	opts, err := ParseOptions([]string{"key=a.pub", "certificate-identity=x@example.com"})
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	if opts[OptionKey] != "a.pub" || opts[OptionCertificateIdentity] != "x@example.com" {
		t.Errorf("ParseOptions = %v", opts)
	}

	for _, bad := range [][]string{{"novalue"}, {"=a"}, {"kye=a.pub"}} {
		if _, err := ParseOptions(bad); err == nil {
			t.Errorf("ParseOptions(%q): nil, want error", bad)
		}
	}
}
