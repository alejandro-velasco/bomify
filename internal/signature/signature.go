// Package signature signs and verifies bomify packages through a signing
// plugin (see plugins/contracts/signing/v1/CONTRACT.md). What's signed is a
// package's OCI manifest descriptor (see Payload): since that manifest pins
// the SBOM config and every component layer by digest, one signature over it
// covers the whole package. A package's vulnerability reports live in a
// referrer of their own (see internal/security), which is signed the same
// way, separately. The plugin only turns that payload into a signature
// envelope and back; bomify itself stores each envelope as an OCI referrer of
// the package's manifest, in whatever target the package lives in — a
// registry or a `bomify save` tarball alike — so a plugin never talks to a
// registry.
package signature

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// AnnotationPlugin is the referrer manifest annotation naming the kind of
// signing plugin that produced its envelope, purely informational.
const AnnotationPlugin = "land.bomify.signature.plugin"

// Plugin is a signing plugin and the options to pass it.
type Plugin struct {
	// Kind names the plugin: bomify-plugin-<Kind>, installed in the
	// plugins directory (see plugin.Dir).
	Kind string
	// Options are passed through, unparsed, as --option flags.
	Options []string
}

// payload is the exact JSON a signing plugin signs. Its fields, their order
// (encoding/json writes them in declaration order), and the absence of
// omitempty are all part of plugins/contracts/signing/v1/CONTRACT.md's
// "Payload" section: changing any of them changes the signed bytes, and so
// invalidates every existing signature.
type payload struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// NewSigner returns a transfer.Signer that signs a package's manifest
// with p and pushes the resulting envelope into the same target as an
// OCI referrer of that manifest: a manifest of p's reported artifact type
// whose subject is the package manifest and whose only layer is the
// envelope. pluginDir is where p's plugin is installed.
func NewSigner(pluginDir string, p Plugin, logger *slog.Logger) (transfer.Signer, error) {
	path, err := plugin.Find(pluginDir, p.Kind, pluginlib.SigningContract)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, target oras.Target, ref string, manifest ocispec.Descriptor) error {
		payloadFile, cleanup, err := writePayload(manifest)
		if err != nil {
			return err
		}
		defer cleanup()

		result, err := signPayload(path, payloadFile, ref, p.Options, logger)
		if err != nil {
			return err
		}
		signatureDesc, err := attachEnvelope(ctx, target, manifest, path, p, result, nil)
		if err != nil {
			return err
		}
		logger.Info("signed", "reference", ref, "plugin", p.Kind, "manifest", manifest.Digest.String(), "signature", signatureDesc.Digest.String())
		return nil
	}, nil
}

// NewAttester returns a transfer.Attester that has p's plugin sign an in-toto
// statement as a DSSE envelope (see
// plugins/contracts/signing/v1/CONTRACT.md's "signature attest") and pushes
// it as a referrer of the package manifest, the same way NewSigner pushes a
// signature.
func NewAttester(pluginDir string, p Plugin, logger *slog.Logger) (transfer.Attester, error) {
	path, err := plugin.Find(pluginDir, p.Kind, pluginlib.SigningContract)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, target oras.Target, ref string, subject ocispec.Descriptor, statement []byte, annotations map[string]string) (ocispec.Descriptor, error) {
		statementFile, err := fsutil.WriteTemp("bomify-attestation-*.json", statement)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		defer os.Remove(statementFile)

		result, err := attestStatement(path, statementFile, ref, p.Options, logger)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		desc, err := attachEnvelope(ctx, target, subject, path, p, result, annotations)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		logger.Info("attested", "reference", ref, "plugin", p.Kind, "manifest", subject.Digest.String(), "attestation", desc.Digest.String())
		return desc, nil
	}, nil
}

// NewSigners returns a transfer.Signer and transfer.Attester that sign
// with each of plugins in turn (see NewSigner and NewAttester), so a
// package carries one signature, and one attestation, per plugin. Every
// plugin is found before any signs. The attester returns the first
// plugin's attestation.
func NewSigners(pluginDir string, plugins []Plugin, logger *slog.Logger) (transfer.Signer, transfer.Attester, error) {
	signers := make([]transfer.Signer, len(plugins))
	attesters := make([]transfer.Attester, len(plugins))
	for index, plugin := range plugins {
		var err error
		if signers[index], err = NewSigner(pluginDir, plugin, logger); err != nil {
			return nil, nil, err
		}
		if attesters[index], err = NewAttester(pluginDir, plugin, logger); err != nil {
			return nil, nil, err
		}
	}

	sign := func(ctx context.Context, target oras.Target, ref string, manifest ocispec.Descriptor) error {
		for _, signer := range signers {
			if err := signer(ctx, target, ref, manifest); err != nil {
				return err
			}
		}
		return nil
	}
	attest := func(ctx context.Context, target oras.Target, ref string, subject ocispec.Descriptor, statement []byte, annotations map[string]string) (ocispec.Descriptor, error) {
		var first ocispec.Descriptor
		for index, attester := range attesters {
			desc, err := attester(ctx, target, ref, subject, statement, annotations)
			if err != nil {
				return ocispec.Descriptor{}, err
			}
			if index == 0 {
				first = desc
			}
		}
		return first, nil
	}
	return sign, attest, nil
}

// attachEnvelope pushes the envelope in result, from the plugin at path,
// as a referrer of subject, annotated with annotations, the plugin's own,
// and AnnotationPlugin.
func attachEnvelope(ctx context.Context, target oras.Target, subject ocispec.Descriptor, path string, p Plugin, result pluginlib.SignResult, annotations map[string]string) (ocispec.Descriptor, error) {
	// All three are required by the contract (see
	// plugins/contracts/signing/v1/CONTRACT.md's SignResult): without them
	// there's no referrer type to push, no media type to hand back to verify,
	// or nothing to store at all.
	if result.ArtifactType == "" || result.MediaType == "" || len(result.Envelope) == 0 {
		return ocispec.Descriptor{}, fmt.Errorf("plugin %s reported an incomplete signing result (artifactType, mediaType, and envelope are all required)", path)
	}

	envelopeDesc, err := transfer.PushBytes(ctx, target, result.Envelope, result.MediaType, "signature", nil)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push signature envelope: %w", err)
	}

	merged := map[string]string{ocispec.AnnotationCreated: time.Now().UTC().Format(time.RFC3339)}
	maps.Copy(merged, result.Annotations)
	maps.Copy(merged, annotations)
	merged[AnnotationPlugin] = p.Kind

	return transfer.PushReferrer(ctx, target, subject, result.ArtifactType, []ocispec.Descriptor{envelopeDesc}, merged, "signature")
}

// NewVerifier returns a transfer.Verifier enforcing policy: for each
// reference, it asks policy which signatures (if any) it must carry (see
// Policy.For), and if it must, requires them (see VerifySigners),
// failing the pull outright otherwise. A reference no policy applies to
// is restored unverified, with a warning when --insecure-skip-verify
// bypasses a trust rule that matched it, since that's a policy being
// deliberately bypassed rather than simply absent. pluginDir is where the
// verifying plugins are installed (see plugin.Dir).
func NewVerifier(pluginDir string, policy Policy, logger *slog.Logger) transfer.Verifier {
	return func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor) error {
		req, required := policy.For(ref)
		if !required {
			if rule, ok := Resolve(policy.Rules, ref); ok && policy.Skip {
				logger.Warn("skipping signature verification required by trust rule", "reference", ref, "match", rule.Match)
			}
			logger.Debug("no signature verification required", "reference", ref)
			return nil
		}
		return VerifySigners(ctx, target, ref, manifest, pluginDir, req, logger)
	}
}

// VerifySigners requires manifest to carry a signature that each of
// req's signers verifies (see VerifySignature), or, with req.Require
// set, that many of them. A single signature can count for two signers
// only if both trust whoever made it. With one signer, its error is
// returned as is; with more, each failing signer's error is named.
func VerifySigners(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, pluginDir string, req Requirement, logger *slog.Logger) error {
	need := req.required()
	var verified int
	var failures []error
	for _, signer := range req.Signers {
		identity, err := VerifySignature(ctx, target, ref, manifest, pluginDir, signer.plugin(), logger)
		if err != nil {
			failure := &SignerError{
				Name: signer.Name,
				Err:  err,
			}
			failures = append(failures, failure)
			continue
		}
		logger.Info("verified", "reference", ref, "plugin", signer.Kind, "signer", identity, "name", signer.Name)
		if verified++; verified == need {
			return nil
		}
	}
	if len(req.Signers) == 1 {
		// A single signer, as with --verify: its own error says it all.
		return errors.Unwrap(failures[0])
	}
	return fmt.Errorf("%s: %d of the %d required signers verified: %w", ref, verified, need, errors.Join(failures...))
}

// VerifySignature requires at least one of manifest's signature referrers in
// target — among those whose artifact type p's plugin reports it
// supports — to pass that plugin's "signature verify", returning the
// signer it reported. It fails if there are no such referrers at all, or
// if every one fails, naming why each did. pluginDir is where p's plugin
// is installed (see plugin.Dir).
func VerifySignature(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, pluginDir string, p Plugin, logger *slog.Logger) (signer string, err error) {
	path, err := plugin.Find(pluginDir, p.Kind, pluginlib.SigningContract)
	if err != nil {
		return "", err
	}

	supported, err := supportedTypes(path, logger)
	if err != nil {
		return "", err
	}

	referrers, err := transfer.Referrers(ctx, target, manifest, "")
	if err != nil {
		return "", err
	}

	var candidates []ocispec.Descriptor
	for _, referrer := range referrers {
		// An attestation (e.g. build provenance) is signed with the same
		// plugin, and so the same artifact type, but over a statement, not
		// the package.
		if referrer.Annotations[transfer.AnnotationAttestation] != "" {
			continue
		}
		if slices.Contains(supported.ArtifactTypes, referrer.ArtifactType) {
			candidates = append(candidates, referrer)
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no signature of %s found that %s can verify (supported artifact types: %s)", manifest.Digest, p.Kind, strings.Join(supported.ArtifactTypes, ", "))
	}

	payloadFile, cleanup, err := writePayload(manifest)
	if err != nil {
		return "", err
	}
	defer cleanup()

	var failures []error
	for _, candidate := range candidates {
		signer, err := verifyReferrer(ctx, target, candidate, path, payloadFile, ref, p.Options, logger)
		if err == nil {
			return signer, nil
		}
		failures = append(failures, fmt.Errorf("signature %s: %w", candidate.Digest, err))
	}

	return "", fmt.Errorf("no signature of %s verified with %s: %w", manifest.Digest, p.Kind, errors.Join(failures...))
}

// verifyReferrer fetches the envelope a single signature referrer
// carries and hands it to the plugin at path to verify.
func verifyReferrer(ctx context.Context, store content.ReadOnlyStorage, referrer ocispec.Descriptor, path, payloadFile, ref string, options []string, logger *slog.Logger) (string, error) {
	envelopeFile, mediaType, err := fetchEnvelope(ctx, store, referrer)
	if err != nil {
		return "", err
	}
	defer os.Remove(envelopeFile)

	result, err := verifyEnvelope(path, payloadFile, envelopeFile, mediaType, ref, options, logger)
	if err != nil {
		return "", err
	}
	return result.Signer, nil
}

// fetchEnvelope writes the envelope referrer carries as its one layer to
// a new temp file, which the caller must remove, returning its path and
// media type.
func fetchEnvelope(ctx context.Context, store content.ReadOnlyStorage, referrer ocispec.Descriptor) (string, string, error) {
	envelopeDesc, envelope, err := transfer.FetchAttachment(ctx, store, referrer, "")
	if err != nil {
		return "", "", fmt.Errorf("fetch envelope: %w", err)
	}

	envelopeFile, err := fsutil.WriteTemp("bomify-signature-envelope-*", envelope)
	if err != nil {
		return "", "", err
	}
	return envelopeFile, envelopeDesc.MediaType, nil
}

// VerifyAttestation requires at least one of manifest's attestation
// referrers of predicateType in target — among those whose artifact type
// p's plugin supports — to pass that plugin's "signature
// verify-attestation" and then check, which inspects the statement the
// plugin returns. It returns that statement and its signer, failing if
// there are no such referrers, or if every one fails, naming why each
// did. pluginDir is where p's plugin is installed (see plugin.Dir).
func VerifyAttestation(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, predicateType, pluginDir string, p Plugin, check func(statement []byte) error, logger *slog.Logger) (statement []byte, signer string, err error) {
	path, err := plugin.Find(pluginDir, p.Kind, pluginlib.SigningContract)
	if err != nil {
		return nil, "", err
	}
	supported, err := supportedTypes(path, logger)
	if err != nil {
		return nil, "", err
	}

	referrers, err := transfer.Referrers(ctx, target, manifest, "")
	if err != nil {
		return nil, "", err
	}
	var candidates []ocispec.Descriptor
	for _, referrer := range referrers {
		if referrer.Annotations[transfer.AnnotationAttestation] == predicateType && slices.Contains(supported.ArtifactTypes, referrer.ArtifactType) {
			candidates = append(candidates, referrer)
		}
	}
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("no %s attestation of %s found that %s can verify (supported artifact types: %s)", predicateType, manifest.Digest, p.Kind, strings.Join(supported.ArtifactTypes, ", "))
	}

	var failures []error
	for _, candidate := range candidates {
		statement, signer, err := verifyAttestationReferrer(ctx, target, candidate, path, manifest.Digest.String(), ref, p.Options, check, logger)
		if err == nil {
			return statement, signer, nil
		}
		failures = append(failures, fmt.Errorf("attestation %s: %w", candidate.Digest, err))
	}
	return nil, "", fmt.Errorf("no %s attestation of %s verified with %s: %w", predicateType, manifest.Digest, p.Kind, errors.Join(failures...))
}

// verifyAttestationReferrer fetches the envelope a single attestation
// referrer carries, has the plugin at path verify it as an attestation
// about subject, and checks the statement it signs.
func verifyAttestationReferrer(ctx context.Context, store content.ReadOnlyStorage, referrer ocispec.Descriptor, path, subject, ref string, options []string, check func([]byte) error, logger *slog.Logger) ([]byte, string, error) {
	envelopeFile, mediaType, err := fetchEnvelope(ctx, store, referrer)
	if err != nil {
		return nil, "", err
	}
	defer os.Remove(envelopeFile)

	result, err := verifyAttestationEnvelope(path, envelopeFile, mediaType, subject, ref, options, logger)
	if err != nil {
		return nil, "", err
	}
	if err := check(result.Statement); err != nil {
		return nil, "", err
	}
	return result.Statement, result.Signer, nil
}

// writePayload writes the payload a signing plugin signs, or verifies a
// signature over, for a package whose OCI manifest is manifest to a new
// temp file, returning its path and a func removing it again. Both the
// sign and verify paths go through here, so they always agree on the
// bytes. Nothing else from manifest is included — in particular not its
// artifactType, which a registry doesn't report when resolving a tag —
// so the payload written at pull time is byte-for-byte the one signed at
// push time.
func writePayload(manifest ocispec.Descriptor) (string, func(), error) {
	p := payload{
		MediaType: manifest.MediaType,
		Digest:    manifest.Digest.String(),
		Size:      manifest.Size,
	}

	data, err := json.Marshal(p)
	if err != nil {
		return "", nil, fmt.Errorf("encode signature payload: %w", err)
	}

	path, err := fsutil.WriteTemp("bomify-signature-payload-*.json", data)
	if err != nil {
		return "", nil, err
	}
	return path, func() { os.Remove(path) }, nil
}
