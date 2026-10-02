package signature

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

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
// provenance (see internal/provenance) about the package, attested by a
// signer the plugin policy.For picks trusts, that passes
// provenance.Check. pluginDir is where that plugin is installed (see
// plugin.Dir).
func NewProvenanceVerifier(pluginDir string, policy Policy, logger *slog.Logger) transfer.Verifier {
	return func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor) error {
		if !policy.ProvenanceRequired(ref) {
			return nil
		}
		p, ok := policy.For(ref)
		if !ok {
			return fmt.Errorf("provenance verification needs a signature verifier: pass --verify or add a \"bomify trust\" rule matching %s", ref)
		}

		sbom, err := configDigest(ctx, target, manifest)
		if err != nil {
			return err
		}
		check := func(statement []byte) error { return provenance.Check(statement, manifest.Digest.Encoded(), sbom) }
		_, signer, err := VerifyAttestation(ctx, target, ref, manifest, provenance.PredicateType, pluginDir, p, check, logger)
		if err != nil {
			return fmt.Errorf("provenance: %w", err)
		}

		logger.Info("provenance verified", "reference", ref, "plugin", p.Kind, "signer", signer)
		return nil
	}
}

// configDigest returns the hex SHA-256 of manifest's config, the
// package's SBOM.
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
	return m.Config.Digest.Encoded(), nil
}
