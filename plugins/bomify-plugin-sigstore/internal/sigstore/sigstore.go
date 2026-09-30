// Package sigstore signs and verifies a bomify signing payload as a
// Sigstore bundle (v0.3), via sigstore-go. Two modes are supported,
// selected by whether a key option is given:
//
//   - Key-based: sign with a local private key and verify against its
//     public key. Nothing is uploaded anywhere and no network access is
//     needed, which suits private registries and air-gapped transfers.
//   - Keyless: sign with a short-lived Fulcio certificate issued for an
//     OIDC identity token (see identityToken) — e.g. a CI workflow's own —
//     recorded in Rekor; verify against the public-good Sigstore trusted
//     root and a required certificate identity/issuer.
package sigstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// Sign signs payload — with the private key opts names, or keyless if it
// names none — returning the resulting Sigstore bundle as JSON. With a
// payloadType, the bundle holds a DSSE envelope over payload of that type
// (e.g. an in-toto attestation) rather than a signature over the raw
// bytes.
func Sign(ctx context.Context, payload []byte, payloadType string, opts Options) ([]byte, error) {
	var (
		kp         sign.Keypair
		bundleOpts = sign.BundleOptions{Context: ctx}
	)

	if keyPath := opts[OptionKey]; keyPath != "" {
		loaded, err := loadKeypair(keyPath)
		if err != nil {
			return nil, err
		}
		kp = loaded
	} else {
		if err := keylessBundleOptions(&bundleOpts, opts); err != nil {
			return nil, err
		}
		ephemeral, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", err)
		}
		kp = ephemeral
	}

	var content sign.Content = &sign.PlainData{Data: payload}
	if payloadType != "" {
		content = &sign.DSSEData{Data: payload, PayloadType: payloadType}
	}
	pb, err := sign.Bundle(content, kp, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return protojson.Marshal(pb)
}

// inTotoPayloadType is the DSSE payload type of an in-toto statement.
const inTotoPayloadType = "application/vnd.in-toto+json"

// BundleAnnotations returns the referrer annotations Sigstore's own tools
// (cosign, gh attestation) use to find an attestation bundle: that it
// holds a DSSE envelope and, for an in-toto statement, its predicate
// type. A plain signature (no payloadType) needs none.
func BundleAnnotations(payload []byte, payloadType string) map[string]string {
	if payloadType == "" {
		return nil
	}
	annotations := map[string]string{"dev.sigstore.bundle.content": "dsse-envelope"}
	if payloadType == inTotoPayloadType {
		var statement struct {
			PredicateType string `json:"predicateType"`
		}
		if json.Unmarshal(payload, &statement) == nil && statement.PredicateType != "" {
			annotations["dev.sigstore.bundle.predicateType"] = statement.PredicateType
		}
	}
	return annotations
}

// keylessBundleOptions points opts at the public-good Sigstore instance's
// Fulcio and Rekor, as its TUF-distributed signing config names them,
// with the identity token Fulcio certifies.
func keylessBundleOptions(opts *sign.BundleOptions, o Options) error {
	token := o.identityToken()
	if token == "" {
		return fmt.Errorf("keyless signing needs an OIDC identity token issued for the %q audience: set %s, or pass --option %s=<path> to sign with a key instead", "sigstore", idTokenEnv, OptionKey)
	}

	signingConfig, err := root.FetchSigningConfig()
	if err != nil {
		return fmt.Errorf("fetch sigstore signing config: %w", err)
	}
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return fmt.Errorf("fetch sigstore trusted root: %w", err)
	}

	now := time.Now()
	fulcio, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, now)
	if err != nil {
		return fmt.Errorf("select fulcio: %w", err)
	}
	rekors, err := root.SelectServices(signingConfig.RekorLogURLs(), signingConfig.RekorLogURLsConfig(), sign.RekorAPIVersions, now)
	if err != nil {
		return fmt.Errorf("select rekor: %w", err)
	}

	opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{BaseURL: fulcio.URL})
	opts.CertificateProviderOptions = &sign.CertificateProviderOptions{IDToken: token}
	opts.TrustedRoot = trustedRoot
	for _, rekor := range rekors {
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{BaseURL: rekor.URL, Version: rekor.MajorAPIVersion}))
	}
	return nil
}

// Verify checks that envelope — a Sigstore bundle as JSON — is a valid
// signature over payload by the signer opts trusts (a public key, or a
// keyless certificate identity and issuer), returning a human-readable
// identity of that signer.
func Verify(payload, envelope []byte, opts Options) (string, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(envelope); err != nil {
		return "", fmt.Errorf("parse bundle: %w", err)
	}

	if keyPath := opts[OptionKey]; keyPath != "" {
		return verifyWithKey(&b, payload, keyPath)
	}
	return verifyKeyless(&b, payload, opts)
}

// verifyWithKey verifies b against the PEM public key at keyPath. The
// bundle's own key hint is deliberately ignored: the only key accepted
// is the one given, whatever the bundle claims.
func verifyWithKey(b *bundle.Bundle, payload []byte, keyPath string) (string, error) {
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

	if _, err := v.Verify(b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(payload)), verify.WithKey())); err != nil {
		return "", err
	}

	hint, err := keyHint(pub)
	if err != nil {
		return "", err
	}
	return "key sha256:" + hint, nil
}

// verifyKeyless verifies b against the public-good Sigstore trusted root,
// requiring its certificate to match the identity and issuer opts name,
// and its signing to be logged in Rekor.
func verifyKeyless(b *bundle.Bundle, payload []byte, opts Options) (string, error) {
	identity, issuer := opts[OptionCertificateIdentity], opts[OptionCertificateOIDCIssuer]
	identityRegexp, issuerRegexp := opts[OptionCertificateIdentityRegexp], opts[OptionCertificateOIDCIssuerRegexp]
	if (identity == "" && identityRegexp == "") || (issuer == "" && issuerRegexp == "") {
		return "", errors.New("keyless verification needs both a certificate identity (certificate-identity or certificate-identity-regexp) and an OIDC issuer (certificate-oidc-issuer or certificate-oidc-issuer-regexp), or a key option to verify against a public key instead")
	}

	certID, err := verify.NewShortCertificateIdentity(issuer, issuerRegexp, identity, identityRegexp)
	if err != nil {
		return "", err
	}

	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return "", fmt.Errorf("fetch sigstore trusted root: %w", err)
	}
	v, err := verify.NewVerifier(trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return "", err
	}

	result, err := v.Verify(b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(payload)), verify.WithCertificateIdentity(certID)))
	if err != nil {
		return "", err
	}

	if result.Signature != nil && result.Signature.Certificate != nil {
		return result.Signature.Certificate.SubjectAlternativeName, nil
	}
	return "keyless", nil
}
