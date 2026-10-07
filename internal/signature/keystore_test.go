package signature

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// writeKeyPEM writes a fresh ECDSA key to dir as PEM — the public half
// ("PUBLIC KEY"), or the private half ("PRIVATE KEY") if private —
// returning its path.
func writeKeyPEM(t *testing.T, dir, name string, private bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY"}
	if private {
		block.Type = "PRIVATE KEY"
		block.Bytes, err = x509.MarshalPKCS8PrivateKey(key)
	} else {
		block.Bytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	}
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestAddKeyAcceptsOnlyPublicPEM(t *testing.T) {
	baseDir, src := t.TempDir(), t.TempDir()

	pub := writeKeyPEM(t, src, "team.pub", false)
	entry, err := AddKey(baseDir, "team", pub)
	if err != nil {
		t.Fatalf("AddKey(public): %v", err)
	}
	if _, err := os.Stat(keyStore(baseDir).Path(entry.SHA256)); err != nil {
		t.Errorf("stored copy missing: %v", err)
	}

	sigstorePrivate := filepath.Join(src, "cosign.key")
	if err := os.WriteFile(sigstorePrivate, []byte("-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	notPEM := filepath.Join(src, "notes.txt")
	if err := os.WriteFile(notPEM, []byte("not a key"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	for name, path := range map[string]string{
		"PKCS#8 private key":   writeKeyPEM(t, src, "team.key", true),
		"sigstore private key": sigstorePrivate,
		"not PEM":              notPEM,
		"missing file":         filepath.Join(src, "missing.pub"),
	} {
		if _, err := AddKey(baseDir, "other", path); err == nil {
			t.Errorf("%s: AddKey error = nil, want one", name)
		}
	}
	if _, err := AddKey(baseDir, "a=b", pub); err == nil {
		t.Error("AddKey accepted a name containing \"=\"")
	}

	keys, err := ListKeys(baseDir)
	if err != nil || len(keys) != 1 || keys[0].Name != "team" {
		t.Errorf("ListKeys = %+v, %v; want just team", keys, err)
	}
}

func TestKeyOptionRules(t *testing.T) {
	baseDir := t.TempDir()
	entry, err := AddKey(baseDir, "team", writeKeyPEM(t, t.TempDir(), "team.pub", false))
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}

	keyed := func(options []string, keyOptions map[string]string) Rule {
		return Rule{Match: "registry.example.com", Signers: []Signer{{Kind: "sigstore", Options: options, KeyOptions: keyOptions}}}
	}
	if err := SetRule(baseDir, keyed([]string{"certificate-identity=x"}, map[string]string{"key": "team"})); err != nil {
		t.Fatalf("SetRule: %v", err)
	}
	if err := SetRule(baseDir, keyed(nil, map[string]string{"key": "missing"})); err == nil {
		t.Error("SetRule accepted an unknown key name")
	}
	if err := SetRule(baseDir, keyed([]string{"key=a.pub"}, map[string]string{"key": "team"})); err == nil {
		t.Error("SetRule accepted the same option as --option and --key-option")
	}

	// Resolved, a key option becomes a plain option pointing at the
	// stored copy, after the signer's own options.
	rules, err := ReadResolved(baseDir)
	if err != nil {
		t.Fatalf("ReadResolved: %v", err)
	}
	want := []string{"certificate-identity=x", "key=" + keyStore(baseDir).Path(entry.SHA256)}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0].Signers[0].Options, want) || rules[0].Signers[0].KeyOptions != nil {
		t.Fatalf("resolved rules = %+v, want options %v", rules, want)
	}

	// The policy hands those options to the verifier.
	req, required := (Policy{Rules: rules}).For("registry.example.com/app:1")
	if !required || !reflect.DeepEqual(req.Signers[0].Options, want) {
		t.Errorf("Policy.For = %+v, %v; want options %v", req, required, want)
	}

	// The stored copy is what counts: rotating the name updates the rule.
	rotated, err := AddKey(baseDir, "team", writeKeyPEM(t, t.TempDir(), "team2.pub", false))
	if err != nil {
		t.Fatalf("AddKey (rotate): %v", err)
	}
	if rules, _ := ReadResolved(baseDir); rules[0].Signers[0].Options[1] != "key="+keyStore(baseDir).Path(rotated.SHA256) {
		t.Errorf("after rotation, options = %v", rules[0].Signers[0].Options)
	}

	// A key a rule uses can't be removed.
	if err := RemoveKey(baseDir, "team"); err == nil {
		t.Error("RemoveKey of a key in use succeeded")
	}
	if err := RemoveRule(baseDir, "registry.example.com"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if err := RemoveKey(baseDir, "team"); err != nil {
		t.Errorf("RemoveKey: %v", err)
	}
}

// TestVerifyWithStoredKey signs with a key file and verifies through a
// trust rule naming the same key in the store: the plugin sees the
// stored copy's path exactly as if it had been passed with --option.
// (The fake signer keys its HMAC on the option's value, the path.)
func TestVerifyWithStoredKey(t *testing.T) {
	installFakeSigner(t)
	ctx := context.Background()
	baseDir := t.TempDir()
	store := newStore(t)
	manifest := pushPackage(t, store, "registry.example.com/team/app:v1", "app")

	entry, err := AddKey(baseDir, "team", writeKeyPEM(t, t.TempDir(), "team.pub", false))
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	sign(t, store, "registry.example.com/team/app:v1", manifest, keyStore(baseDir).Path(entry.SHA256))

	if err := SetRule(baseDir, Rule{Match: "registry.example.com/team", Signers: []Signer{{Kind: fakeKind, KeyOptions: map[string]string{"key": "team"}}}}); err != nil {
		t.Fatalf("SetRule: %v", err)
	}
	verifierFor := func() func() error {
		rules, err := ReadResolved(baseDir)
		if err != nil {
			t.Fatalf("ReadResolved: %v", err)
		}
		v := NewVerifier(pluginDir, Policy{Rules: rules}, discardLogger())
		return func() error { return v(ctx, store, "registry.example.com/team/app:v1", manifest) }
	}

	if err := verifierFor()(); err != nil {
		t.Errorf("verify with the stored key: %v", err)
	}

	// Rotating "team" to another key means the old signature no longer
	// verifies against the rule.
	if _, err := AddKey(baseDir, "team", writeKeyPEM(t, t.TempDir(), "rotated.pub", false)); err != nil {
		t.Fatalf("AddKey (rotate): %v", err)
	}
	if err := verifierFor()(); err == nil {
		t.Error("verify after rotating the stored key: nil, want an error")
	}
}

// TestCheckPublicPEM covers the allowlist: each block must be a
// certificate or public key that actually parses; anything else —
// including a private key under a public label — is refused.
func TestCheckPublicPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	encode := func(blocks ...*pem.Block) []byte {
		var out []byte
		for _, b := range blocks {
			out = append(out, pem.EncodeToMemory(b)...)
		}
		return out
	}

	for name, tt := range map[string]struct {
		data []byte
		ok   bool
	}{
		"PKIX public key":       {encode(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}), true},
		"certificate":           {encode(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), true},
		"PKCS#1 RSA public key": {encode(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)}), true},
		"key plus certificate":  {encode(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}, &pem.Block{Type: "CERTIFICATE", Bytes: cert}), true},

		"private key":                 {encode(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), false},
		"private key labeled public":  {encode(&pem.Block{Type: "PUBLIC KEY", Bytes: pkcs8}), false},
		"public key then private key": {encode(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}, &pem.Block{Type: "EC PRIVATE KEY", Bytes: pkcs8}), false},
		"unfamiliar label":            {encode(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08}}), false},
		"corrupt public key":          {encode(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}), false},
		"not PEM":                     {[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host"), false},
	} {
		if err := checkPublicPEM(tt.data); (err == nil) != tt.ok {
			t.Errorf("%s: checkPublicPEM() error = %v, want ok = %v", name, err, tt.ok)
		}
	}
}
