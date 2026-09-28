// Package signature signs and verifies bomify packages through a
// signing plugin (see plugins/SIGNING-CONTRACT.md). What's signed is a
// package's OCI manifest descriptor (see Payload): since that manifest
// pins the SBOM config, every component layer, and every vulnerability
// report by digest, one signature over it covers the whole package. The
// plugin only turns that payload into a signature envelope and back;
// bomify itself stores each envelope as an OCI referrer of the package's
// manifest, in whatever target the package lives in — a registry or a
// `bomify save` tarball alike — so a plugin never talks to a registry.
package signature

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

// AnnotationPlugin is the referrer manifest annotation naming the kind of
// signing plugin that produced its envelope, purely informational.
const AnnotationPlugin = "land.bomify.signature.plugin"

// maxEnvelopeSize bounds how large an envelope Verify will fetch from a
// referrer. Envelopes are published by whoever could push to the
// repository — not necessarily whoever bomify trusts — so this keeps a
// hostile referrer from making bomify download something arbitrarily
// large before a plugin ever looks at it.
const maxEnvelopeSize = 4 << 20

// Plugin is a signing plugin and the options to pass it.
type Plugin struct {
	// Kind names the plugin: bomify-plugin-<Kind> on PATH.
	Kind string
	// Options are passed through, unparsed, as --option flags.
	Options []string
}

// Payload returns the exact bytes a signing plugin signs, and later
// verifies a signature over, for a package whose OCI manifest is
// manifest: a JSON object of just its mediaType, digest, and size, in
// that order. Nothing else from manifest is included — in particular
// not its artifactType, which a registry doesn't report when resolving
// a tag — so the payload computed at pull time is byte-for-byte the one
// signed at push time.
func Payload(manifest ocispec.Descriptor) ([]byte, error) {
	payload := struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}{
		MediaType: manifest.MediaType,
		Digest:    manifest.Digest.String(),
		Size:      manifest.Size,
	}
	return json.Marshal(payload)
}

// NewSigner returns a transfer.Signer that signs a package's manifest
// with p and pushes the resulting envelope into the same target as an
// OCI referrer of that manifest — a manifest of p's reported artifact
// type whose subject is the package manifest and whose only layer is the
// envelope.
func NewSigner(p Plugin, logger *slog.Logger) (transfer.Signer, error) {
	path, err := plugin.Find(p.Kind)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, target oras.Target, ref string, manifest ocispec.Descriptor) error {
		payloadFile, cleanup, err := writePayload(manifest)
		if err != nil {
			return err
		}
		defer cleanup()

		result, err := plugin.Sign(path, payloadFile, ref, p.Options, logger)
		if err != nil {
			return err
		}
		if result.ArtifactType == "" || result.MediaType == "" || len(result.Envelope) == 0 {
			return fmt.Errorf("plugin %s signature sign reported an incomplete result (artifactType, mediaType, and envelope are all required)", path)
		}

		envelopeDesc, err := transfer.PushBytes(ctx, target, result.Envelope, result.MediaType, "signature", nil)
		if err != nil {
			return fmt.Errorf("push signature envelope: %w", err)
		}

		annotations := map[string]string{}
		for k, v := range result.Annotations {
			annotations[k] = v
		}
		annotations[AnnotationPlugin] = p.Kind

		subject := ocispec.Descriptor{MediaType: manifest.MediaType, Digest: manifest.Digest, Size: manifest.Size}
		signatureDesc, err := oras.PackManifest(ctx, target, oras.PackManifestVersion1_1, result.ArtifactType, oras.PackManifestOptions{
			Subject:             &subject,
			Layers:              []ocispec.Descriptor{envelopeDesc},
			ManifestAnnotations: annotations,
		})
		if err != nil {
			return fmt.Errorf("push signature referrer: %w", err)
		}

		logger.Info("signed", "reference", ref, "plugin", p.Kind, "manifest", manifest.Digest.String(), "signature", signatureDesc.Digest.String())
		return nil
	}, nil
}

// NewVerifier returns a transfer.Verifier enforcing policy: for each
// reference, it asks policy which plugin (if any) must verify it (see
// Policy.For), and if one must, requires at least one of the manifest's
// signature referrers to pass that plugin's "signature verify" — failing
// the pull outright otherwise. A reference no policy applies to is
// restored unverified.
func NewVerifier(policy Policy, logger *slog.Logger) transfer.Verifier {
	return func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor) error {
		p, required := policy.For(ref, logger)
		if !required {
			logger.Debug("no signature verification required", "reference", ref)
			return nil
		}

		signer, err := Verify(ctx, target, ref, manifest, p, logger)
		if err != nil {
			return err
		}

		logger.Info("verified", "reference", ref, "plugin", p.Kind, "signer", signer)
		return nil
	}
}

// Verify requires at least one of manifest's signature referrers in
// target — among those whose artifact type p's plugin reports it
// supports — to pass that plugin's "signature verify", returning the
// signer it reported. It fails if there are no such referrers at all, or
// if every one fails, naming why each did.
func Verify(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, p Plugin, logger *slog.Logger) (signer string, err error) {
	path, err := plugin.Find(p.Kind)
	if err != nil {
		return "", err
	}

	graph, ok := target.(content.ReadOnlyGraphStorage)
	if !ok {
		return "", fmt.Errorf("cannot list signatures: %T does not support referrers", target)
	}

	supported, err := plugin.SupportedSignatureTypes(path, logger)
	if err != nil {
		return "", err
	}

	referrers, err := registry.Referrers(ctx, graph, manifest, "")
	if err != nil {
		return "", fmt.Errorf("list signatures of %s: %w", manifest.Digest, err)
	}

	var candidates []ocispec.Descriptor
	for _, referrer := range referrers {
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
		signer, err := verifyReferrer(ctx, graph, candidate, path, payloadFile, ref, p.Options, logger)
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
	data, err := content.FetchAll(ctx, store, referrer)
	if err != nil {
		return "", fmt.Errorf("fetch referrer: %w", err)
	}

	var m ocispec.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("parse referrer: %w", err)
	}
	if len(m.Layers) != 1 {
		return "", fmt.Errorf("referrer has %d layers, want exactly 1 (the envelope)", len(m.Layers))
	}

	envelopeDesc := m.Layers[0]
	if envelopeDesc.Size > maxEnvelopeSize {
		return "", fmt.Errorf("envelope is %d bytes, larger than the %d allowed", envelopeDesc.Size, maxEnvelopeSize)
	}

	envelope, err := content.FetchAll(ctx, store, envelopeDesc)
	if err != nil {
		return "", fmt.Errorf("fetch envelope: %w", err)
	}

	envelopeFile, err := writeTemp("bomify-signature-envelope-*", envelope)
	if err != nil {
		return "", err
	}
	defer os.Remove(envelopeFile)

	result, err := plugin.VerifySignature(path, payloadFile, envelopeFile, envelopeDesc.MediaType, ref, options, logger)
	if err != nil {
		return "", err
	}
	return result.Signer, nil
}

// writePayload writes manifest's Payload to a new temp file, returning
// its path and a func removing it again.
func writePayload(manifest ocispec.Descriptor) (string, func(), error) {
	payload, err := Payload(manifest)
	if err != nil {
		return "", nil, fmt.Errorf("encode signature payload: %w", err)
	}

	path, err := writeTemp("bomify-signature-payload-*.json", payload)
	if err != nil {
		return "", nil, err
	}
	return path, func() { os.Remove(path) }, nil
}

// writeTemp writes data to a new temp file matching pattern and returns
// its path, which the caller must remove.
func writeTemp(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write %s: %w", f.Name(), err)
	}
	return f.Name(), nil
}
