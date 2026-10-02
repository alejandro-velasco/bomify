package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
)

// AnnotationStatement is the provenance referrer annotation holding the
// SHA-256 of the statement it carries, so pushing the same provenance
// again attaches nothing new, even signed, whose envelope differs every
// time.
const AnnotationStatement = "land.bomify.provenance.statement"

// Attach attaches baseDir's provenance for the build of sbomHash, if it
// recorded any, to that package's manifest in target, as an in-toto
// statement whose subject is the manifest and ref's repository. attest
// signs it as a DSSE attestation; without one, the statement is attached
// unsigned. attached is false when there's no provenance, or the package
// already carries this very statement.
func Attach(ctx context.Context, target oras.Target, ref, baseDir, sbomHash string, manifest ocispec.Descriptor, attest transfer.Attester) (referrer ocispec.Descriptor, attached bool, err error) {
	p, ok, err := Read(baseDir, sbomHash)
	if err != nil || !ok {
		return ocispec.Descriptor{}, false, err
	}

	statement, err := NewStatement(p, prefix.Repository(ref), manifest.Digest.Encoded())
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	sum := sha256.Sum256(statement)
	statementHash := hex.EncodeToString(sum[:])

	existing, err := transfer.Referrers(ctx, target, manifest, "")
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	for _, r := range existing {
		if r.Annotations[AnnotationStatement] == statementHash {
			return r, false, nil
		}
	}

	annotations := map[string]string{
		AnnotationStatement:            statementHash,
		transfer.AnnotationAttestation: PredicateType,
		ocispec.AnnotationCreated:      time.Now().UTC().Format(time.RFC3339Nano),
	}
	if attest != nil {
		referrer, err = attest(ctx, target, ref, manifest, statement, annotations)
		if err != nil {
			return ocispec.Descriptor{}, false, fmt.Errorf("sign provenance: %w", err)
		}
		return referrer, true, nil
	}

	layer, err := transfer.PushBytes(ctx, target, statement, MediaType, "provenance", nil)
	if err != nil {
		return ocispec.Descriptor{}, false, fmt.Errorf("push provenance: %w", err)
	}
	referrer, err = transfer.PushReferrer(ctx, target, manifest, MediaType, []ocispec.Descriptor{layer}, annotations, "provenance")
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	return referrer, true, nil
}
