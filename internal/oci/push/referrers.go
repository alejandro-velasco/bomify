package push

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/provenance"
	"github.com/alejandro-velasco/bomify/internal/security"
)

// referrerAttacher attaches referrers to manifest, a package pushed but
// not yet tagged as ref, signing each, and the manifest itself, before ref
// names it (see Push).
type referrerAttacher struct {
	target   oras.Target
	ref      string
	manifest ocispec.Descriptor
	// signer, if set, signs the manifest and each referrer (see
	// transfer.Signer).
	signer   transfer.Signer
	progress transfer.ProgressFunc
}

// sign signs desc, which what names in an error, if p has a signer.
func (p referrerAttacher) sign(ctx context.Context, desc ocispec.Descriptor, what string) error {
	if p.signer == nil {
		return nil
	}
	if err := p.signer(ctx, p.target, p.ref, desc); err != nil {
		return fmt.Errorf("sign %s: %w", what, err)
	}
	return nil
}

// attachReports attaches components' local vulnerability reports, under
// baseDir, as one signed referrer (see security.Attach), returning it and
// the reports it carries, or nothing if no component has a report.
func (p referrerAttacher) attachReports(ctx context.Context, baseDir string, components []cdx.Component) (ocispec.Descriptor, []PushedLayer, error) {
	referrer, attached, ok, err := security.Attach(ctx, p.target, p.manifest, baseDir, components, p.progress)
	if err != nil {
		return ocispec.Descriptor{}, nil, fmt.Errorf("attach vulnerability reports: %w", err)
	}
	if !ok {
		return ocispec.Descriptor{}, nil, nil
	}
	if err := p.sign(ctx, referrer, "vulnerability reports of "+p.ref); err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	var reports []PushedLayer
	for _, report := range attached {
		layer := PushedLayer{
			Purl: report.Purl,
			Hash: report.Hash,
		}
		reports = append(reports, layer)
	}
	return referrer, reports, nil
}

// attachDocuments attaches each of attachments as a signed referrer of
// its own (see transfer.Attach), returning those it attached: none for a
// document the package already carries.
func (p referrerAttacher) attachDocuments(ctx context.Context, attachments []transfer.Attachment) ([]ocispec.Descriptor, error) {
	var attached []ocispec.Descriptor
	for _, attachment := range attachments {
		referrer, added, err := transfer.Attach(ctx, p.target, p.manifest, attachment, p.progress)
		if err != nil {
			return nil, fmt.Errorf("attach %s: %w", attachment.Name, err)
		}
		if !added {
			continue
		}
		if err := p.sign(ctx, referrer, attachment.Name+" of "+p.ref); err != nil {
			return nil, err
		}
		attached = append(attached, referrer)
	}
	return attached, nil
}

// attachProvenance attaches the build provenance recorded under baseDir
// for sbomHash, signed by attest if set (see provenance.Attach),
// returning it, or the zero Descriptor if the build recorded none or the
// package already carries it.
func (p referrerAttacher) attachProvenance(ctx context.Context, baseDir, sbomHash string, attest transfer.Attester) (ocispec.Descriptor, error) {
	referrer, attached, err := provenance.Attach(ctx, p.target, p.ref, baseDir, sbomHash, p.manifest, attest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("attach provenance: %w", err)
	}
	if !attached {
		return ocispec.Descriptor{}, nil
	}
	return referrer, nil
}
