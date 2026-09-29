package sigstore

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// keypair is a sign.Keypair backed by a long-lived private key loaded
// from disk, rather than sigstore-go's own EphemeralKeypair (which only
// ever generates a fresh one).
type keypair struct {
	signer crypto.Signer
	alg    signature.AlgorithmDetails
	hint   []byte
}

// loadKeypair reads the PEM private key at path, decrypting it with
// SIGSTORE_PASSWORD if it's encrypted.
func loadKeypair(path string) (*keypair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	priv, err := cryptoutils.UnmarshalPEMToPrivateKey(data, func(bool) ([]byte, error) {
		return []byte(os.Getenv(passwordEnv)), nil
	})
	if err != nil {
		return nil, fmt.Errorf("load private key %s: %w", path, err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key %s: unsupported key type %T", path, priv)
	}

	alg, err := signature.GetDefaultAlgorithmDetails(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("private key %s: %w", path, err)
	}

	hint, err := keyHint(signer.Public())
	if err != nil {
		return nil, err
	}

	return &keypair{signer: signer, alg: alg, hint: []byte(hint)}, nil
}

// keyHint returns the fingerprint a bundle carries to identify pub:
// base64(sha256(PKIX DER)), the same scheme sigstore-go's own
// EphemeralKeypair uses.
func keyHint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func (k *keypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.alg.GetProtoHashType()
}

func (k *keypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.alg.GetSignatureAlgorithm()
}

func (k *keypair) GetHint() []byte {
	return k.hint
}

func (k *keypair) GetKeyAlgorithm() string {
	switch k.alg.GetKeyType() {
	case signature.ECDSA:
		return "ECDSA"
	case signature.RSA:
		return "RSA"
	case signature.ED25519:
		return "ED25519"
	default:
		return ""
	}
}

func (k *keypair) GetPublicKey() crypto.PublicKey {
	return k.signer.Public()
}

func (k *keypair) GetPublicKeyPem() (string, error) {
	pem, err := cryptoutils.MarshalPublicKeyToPEM(k.signer.Public())
	if err != nil {
		return "", err
	}
	return string(pem), nil
}

// SignData signs data, returning the signature and what was actually
// signed: data's digest, except for pure Ed25519, which hashes as part
// of signing — mirroring sigstore-go's own EphemeralKeypair.
func (k *keypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.alg.GetHashType()
	toSign := data
	if hf != crypto.Hash(0) {
		h := hf.New()
		h.Write(data)
		toSign = h.Sum(nil)
	}
	sig, err := k.signer.Sign(rand.Reader, toSign, hf)
	if err != nil {
		return nil, nil, err
	}
	return sig, toSign, nil
}
