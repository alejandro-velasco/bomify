// Package sigstore signs and verifies a bomify signing payload as a
// Sigstore bundle (v0.3), via sigstore-go, using a key pair: sign with a
// local private key and verify against its public key. Nothing is
// uploaded anywhere and no network access is needed, which suits private
// registries and air-gapped transfers.
package sigstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

// BundleMediaType is both the referrer artifact type and the envelope
// media type this plugin reports: the one Sigstore itself uses for a
// v0.3 bundle.
const BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// Sign signs payload with the private key opts names, returning the
// resulting Sigstore bundle as JSON.
func Sign(ctx context.Context, payload []byte, opts Options) ([]byte, error) {
	kp, err := loadKeypair(opts[OptionKey])
	if err != nil {
		return nil, err
	}

	pb, err := sign.Bundle(&sign.PlainData{Data: payload}, kp, sign.BundleOptions{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return protojson.Marshal(pb)
}

// Verify checks that envelope — a Sigstore bundle as JSON — is a valid
// signature over payload by the public key opts names, returning that
// key's fingerprint as the signer. The bundle's own key hint is
// deliberately ignored: the only key accepted is the one given, whatever
// the bundle claims.
func Verify(payload, envelope []byte, opts Options) (string, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(envelope); err != nil {
		return "", fmt.Errorf("parse bundle: %w", err)
	}

	keyPath := opts[OptionKey]
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read key: %w", err)
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(data)
	if err != nil {
		return "", fmt.Errorf("load public key %s: %w", keyPath, err)
	}
	verifier, err := signature.LoadDefaultVerifier(pub)
	if err != nil {
		return "", fmt.Errorf("public key %s: %w", keyPath, err)
	}

	trusted := root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(verifier, time.Time{}, time.Time{}), nil
	})
	v, err := verify.NewVerifier(trusted, verify.WithNoObserverTimestamps())
	if err != nil {
		return "", err
	}

	if _, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(payload)), verify.WithKey())); err != nil {
		return "", err
	}

	hint, err := keyHint(pub)
	if err != nil {
		return "", err
	}
	return "key sha256:" + hint, nil
}
