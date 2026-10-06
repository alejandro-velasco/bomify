package signature

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/provenance"
)

// maxManifestSize bounds the package manifest NewProvenanceVerifier
// reads for its SBOM digest, as transfer bounds referrers.
const maxManifestSize = 4 << 20

// NewProvenanceVerifier returns a transfer.Verifier requiring, for each
// reference policy says needs it (see Policy.ProvenanceRequired), build
// provenance (see internal/provenance) about the package, attested by
// someone one of the signers policy.For picks trusts, that passes
// provenance.Check. One trusted attestation is enough, whatever the
// rule's Require. pluginDir is where the signers' plugins are installed
// (see plugin.Dir).
func NewProvenanceVerifier(pluginDir string, policy Policy, logger *slog.Logger) transfer.Verifier {
	return func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor) error {
		if !policy.ProvenanceRequired(ref) {
			return nil
		}
		req, ok := policy.For(ref)
		if !ok {
			return fmt.Errorf("provenance verification needs a signature verifier: pass --verify or add a \"bomify trust\" rule matching %s", ref)
		}

		if !isSHA256(manifest.Digest) {
			return fmt.Errorf("provenance: manifest digest %s isn't SHA-256, as provenance names packages by", manifest.Digest)
		}
		sbom, err := configDigest(ctx, target, manifest)
		if err != nil {
			return err
		}
		check := func(statement []byte) error { return provenance.Check(statement, manifest.Digest.Encoded(), sbom) }

		var failures []error
		for _, signer := range req.Signers {
			_, identity, err := VerifyAttestation(ctx, target, ref, manifest, provenance.PredicateType, pluginDir, signer.plugin(), check, logger)
			if err == nil {
				logger.Info("provenance verified", "reference", ref, "plugin", signer.Verifier, "signer", identity, "name", signer.Name)
				return nil
			}
			failure := &SignerError{
				Name: signer.Name,
				Err:  err,
			}
			failures = append(failures, failure)
		}
		if len(req.Signers) == 1 {
			// A single signer, as with --verify: its own error says it all.
			return fmt.Errorf("provenance: %w", errors.Unwrap(failures[0]))
		}
		return fmt.Errorf("provenance: no signer verified it: %w", errors.Join(failures...))
	}
}

// configDigest returns the hex SHA-256 of manifest's config, the
// package's SBOM, failing unless it's a SHA-256 digest, as provenance
// names SBOMs by.
func configDigest(ctx context.Context, target oras.ReadOnlyTarget, manifest ocispec.Descriptor) (string, error) {
	if manifest.Size > maxManifestSize {
		return "", fmt.Errorf("manifest %s is %d bytes, larger than the %d allowed", manifest.Digest, manifest.Size, maxManifestSize)
	}
	data, err := content.FetchAll(ctx, target, manifest)
	if err != nil {
		return "", fmt.Errorf("fetch manifest %s: %w", manifest.Digest, err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("parse manifest %s: %w", manifest.Digest, err)
	}
	if !isSHA256(m.Config.Digest) {
		return "", fmt.Errorf("provenance: SBOM digest %q in manifest %s isn't SHA-256", m.Config.Digest, manifest.Digest)
	}
	return m.Config.Digest.Encoded(), nil
}

// isSHA256 reports whether d is a valid SHA-256 digest.
func isSHA256(d digest.Digest) bool {
	return d.Validate() == nil && d.Algorithm() == digest.SHA256
}
