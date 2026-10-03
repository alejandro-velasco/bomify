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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/opencontainers/go-digest"
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

// Sign signs payload's raw bytes — with the private key opts names, or
// keyless if it names none — returning the resulting Sigstore bundle as
// JSON.
func Sign(ctx context.Context, payload []byte, opts Options) ([]byte, error) {
	return signBundle(ctx, &sign.PlainData{Data: payload}, opts)
}

// Attest signs statement, an in-toto statement, as Sign does, but as a
// DSSE envelope: the bundle form cosign and gh attestation verify read.
func Attest(ctx context.Context, statement []byte, opts Options) ([]byte, error) {
	return signBundle(ctx, &sign.DSSEData{Data: statement, PayloadType: pluginlib.InTotoPayloadType}, opts)
}

// signBundle signs content with the key or keyless identity opts names,
// returning the Sigstore bundle as JSON.
func signBundle(ctx context.Context, content sign.Content, opts Options) ([]byte, error) {
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

	pb, err := sign.Bundle(content, kp, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return protojson.Marshal(pb)
}

// AttestationAnnotations returns the referrer annotations Sigstore's own
// tools (cosign, gh attestation) use to find an Attest bundle: that it
// holds a DSSE envelope and, if statement names one, its predicate type.
func AttestationAnnotations(statement []byte) map[string]string {
	annotations := map[string]string{"dev.sigstore.bundle.content": "dsse-envelope"}
	var s struct {
		PredicateType string `json:"predicateType"`
	}
	if json.Unmarshal(statement, &s) == nil && s.PredicateType != "" {
		annotations["dev.sigstore.bundle.predicateType"] = s.PredicateType
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
	return verifyBundle(&b, verify.WithArtifact(bytes.NewReader(payload)), opts)
}

// VerifyAttestation checks that envelope — a Sigstore bundle as JSON —
// holds a DSSE envelope of an in-toto statement naming subject
// ("<algorithm>:<hex>") as a subject, validly signed by the signer opts
// trusts, as Verify does. It returns that signer and the statement.
func VerifyAttestation(envelope []byte, subject string, opts Options) (signer string, statement []byte, err error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(envelope); err != nil {
		return "", nil, fmt.Errorf("parse bundle: %w", err)
	}
	dsse, err := b.Envelope()
	if err != nil {
		return "", nil, fmt.Errorf("bundle holds no DSSE envelope: %w", err)
	}
	if dsse.PayloadType != pluginlib.InTotoPayloadType {
		return "", nil, fmt.Errorf("DSSE payload type is %q, want %q", dsse.PayloadType, pluginlib.InTotoPayloadType)
	}

	d, err := digest.Parse(subject)
	if err != nil {
		return "", nil, fmt.Errorf("subject %q: %w", subject, err)
	}
	sum, err := hex.DecodeString(d.Encoded())
	if err != nil {
		return "", nil, fmt.Errorf("subject %q: %w", subject, err)
	}
	if signer, err = verifyBundle(&b, verify.WithArtifactDigest(d.Algorithm().String(), sum), opts); err != nil {
		return "", nil, err
	}

	statement, err = dsse.DecodeB64Payload()
	if err != nil {
		return "", nil, fmt.Errorf("decode statement: %w", err)
	}
	return signer, statement, nil
}

// verifyBundle verifies b against artifact with the key opts names, or
// keyless if it names none.
func verifyBundle(b *bundle.Bundle, artifact verify.ArtifactPolicyOption, opts Options) (string, error) {
	if keyPath := opts[OptionKey]; keyPath != "" {
		return verifyWithKey(b, artifact, keyPath)
	}
	return verifyKeyless(b, artifact, opts)
}

// verifyWithKey verifies b, over artifact, against the PEM public key at keyPath. The
// bundle's own key hint is deliberately ignored: the only key accepted
// is the one given, whatever the bundle claims.
func verifyWithKey(b *bundle.Bundle, artifact verify.ArtifactPolicyOption, keyPath string) (string, error) {
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

	if _, err := v.Verify(b, verify.NewPolicy(artifact, verify.WithKey())); err != nil {
		return "", err
	}

	hint, err := keyHint(pub)
	if err != nil {
		return "", err
	}
	return "key sha256:" + hint, nil
}

// verifyKeyless verifies b, over artifact, against the public-good Sigstore trusted root,
// requiring its certificate to match the identity and issuer opts name,
// and its signing to be logged in Rekor.
func verifyKeyless(b *bundle.Bundle, artifact verify.ArtifactPolicyOption, opts Options) (string, error) {
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

	result, err := v.Verify(b, verify.NewPolicy(artifact, verify.WithCertificateIdentity(certID)))
	if err != nil {
		return "", err
	}

	if result.Signature != nil && result.Signature.Certificate != nil {
		return result.Signature.Certificate.SubjectAlternativeName, nil
	}
	return "keyless", nil
}
