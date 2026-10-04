package security

import (
	"context"
	"log/slog"
	"slices"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// Attachment returns d as a transfer.Attachment: attached to a package
// as a VEX referrer of its own, so its statements travel with it.
func (d VEXDocument) Attachment() transfer.Attachment {
	return transfer.Attachment{
		ArtifactType: transfer.VEXArtifactType,
		MediaType:    transfer.VEXDocumentMediaType,
		Name:         d.Name,
		Data:         d.Data,
	}
}

// PublishedVEX loads the VEX documents attached to the package ref
// resolved to in target — its manifest, manifest (see
// VEXDocument.Attachment) — oldest first, so a later publication's
// statements win over an earlier one's.
//
// Only documents verify accepts count: a VEX document only ever tells a
// gate not to fail, so anyone who could push to the repository could
// otherwise silence any finding. A nil verify — a pull that verifies no
// signatures — counts none. A document that can't be listed, verified,
// fetched, or read is skipped with a warning rather than failing the
// pull, since skipping one can only make the gate stricter.
func PublishedVEX(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, verify transfer.Verifier, logger *slog.Logger) *VEX {
	referrers, err := transfer.Referrers(ctx, target, manifest, transfer.VEXArtifactType)
	if err != nil {
		logger.Warn("ignoring the package's VEX documents: can't list them", "reference", ref, "error", err)
		return nil
	}
	if len(referrers) == 0 {
		return nil
	}
	if verify == nil {
		logger.Warn("ignoring the package's VEX documents: they only count on a pull that verifies signatures (--verify, or a \"bomify trust\" rule)", "reference", ref, "documents", len(referrers))
		return nil
	}

	var published *VEX
	slices.Reverse(referrers)
	for _, referrer := range referrers {
		log := logger.With("reference", ref, "document", referrer.Digest.String())
		if err := verify(ctx, target, ref, referrer); err != nil {
			log.Warn("ignoring an unverified VEX document", "error", err)
			continue
		}
		_, data, err := transfer.FetchAttachment(ctx, target, referrer, transfer.VEXDocumentMediaType)
		if err != nil {
			log.Warn("ignoring a VEX document that can't be fetched", "error", err)
			continue
		}
		v, err := LoadVEXDocuments([]VEXDocument{{Name: "published with " + ref + ": " + referrer.Digest.String(), Data: data}})
		if err != nil {
			log.Warn("ignoring a VEX document that can't be read", "error", err)
			continue
		}
		published = CombineVEX(published, v)
	}
	return published
}
