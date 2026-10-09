// Package push publishes a bomify package as an OCI artifact: the
// counterpart to internal/oci/pull. Push packages the SBOM manifest a prior
// `bomify build` recorded (see internal/build) as the artifact's config,
// and each component that SBOM describes as layers annotated with its
// purl — tars of whatever build pulled for it, and each large file in
// parts (see transfer.FilePartMediaType) — then pushes the whole thing to
// a registry under a tag.
package push

import (
	"context"
	"fmt"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
)

// PushedLayer describes one component layer, or one component's
// vulnerability report, that was pushed.
type PushedLayer struct {
	Purl string
	Hash string
}

// Result is the outcome of a successful Push.
type Result struct {
	// Manifest is the pushed package manifest ref now points at.
	Manifest       ocispec.Descriptor
	ManifestDigest string
	Layers         []PushedLayer
	// VulnerabilityReports lists the components whose local vulnerability
	// report (see internal/security) was attached to the package, as
	// layers of ReportsReferrer — only ever a subset of Layers, since
	// most components carry none.
	VulnerabilityReports []PushedLayer
	// ReportsReferrer is the vulnerability report referrer attached to
	// Manifest (see security.Attach), or the zero Descriptor if no
	// component had a local report.
	ReportsReferrer ocispec.Descriptor
	// Attached are the referrers this push attached for opts.Attach — none
	// for a document the package already carried.
	Attached []ocispec.Descriptor
	// Provenance is the build provenance referrer this push attached (see
	// internal/provenance), or the zero Descriptor if the build recorded
	// none or the package already carried it.
	Provenance ocispec.Descriptor
}

// Push packages the build recorded under baseDir for sbomHash (see
// build.RecordManifest) as an OCI artifact — the manifest itself as the
// config, and each component it describes as a layer — and pushes it to
// target, tagging the result ref. Every component's local vulnerability
// report (see internal/security), if any, is attached as one OCI referrer
// of that manifest rather than as part of it (see security.Attach), so
// re-scanning never changes the package's digest. Layers upload
// concurrently, bounded by opts.Concurrency. Each of opts.Attach is
// attached as a referrer of its own too (see transfer.Attach), and so is
// the build's provenance, if it recorded any, signed by opts.Attest if set
// (see provenance.Attach). A non-nil opts.Sign is called with the packed
// manifest, and then with every other referrer this push attached, before
// ref is tagged (see transfer.Signer), so a signing failure never leaves
// ref pointing at an unsigned package.
func Push(ctx context.Context, target oras.Target, ref, baseDir, sbomHash string, opts transfer.Options) (Result, error) {
	opts = opts.WithDefaults()

	pkg, err := pushPackage(ctx, target, baseDir, sbomHash, opts)
	if err != nil {
		return Result{}, err
	}

	attacher := referrerAttacher{
		target:   target,
		ref:      ref,
		manifest: pkg.desc,
		signer:   opts.Sign,
		progress: opts.Progress,
	}
	if err := attacher.sign(ctx, pkg.desc, ref); err != nil {
		return Result{}, err
	}
	reportsReferrer, reports, err := attacher.attachReports(ctx, baseDir, pkg.components)
	if err != nil {
		return Result{}, err
	}
	attached, err := attacher.attachDocuments(ctx, opts.Attach)
	if err != nil {
		return Result{}, err
	}
	provenanceReferrer, err := attacher.attachProvenance(ctx, baseDir, sbomHash, opts.Attest)
	if err != nil {
		return Result{}, err
	}

	if err := target.Tag(ctx, pkg.desc, ref); err != nil {
		return Result{}, fmt.Errorf("tag %s: %w", ref, err)
	}

	result := Result{
		Manifest:             pkg.desc,
		ManifestDigest:       pkg.desc.Digest.String(),
		Layers:               pkg.layers,
		VulnerabilityReports: reports,
		ReportsReferrer:      reportsReferrer,
		Attached:             attached,
		Provenance:           provenanceReferrer,
	}
	return result, nil
}

// pushedPackage is the package Push has pushed, but not yet tagged: its
// manifest's descriptor, the components its SBOM describes, and their
// layers.
type pushedPackage struct {
	desc       ocispec.Descriptor
	components []cdx.Component
	layers     []PushedLayer
}

// pushPackage pushes the build recorded under baseDir for sbomHash: its
// SBOM as the config (see pushConfig), each component's layers, up to
// opts.Concurrency at once, and then the manifest packing them.
func pushPackage(ctx context.Context, target oras.Target, baseDir, sbomHash string, opts transfer.Options) (*pushedPackage, error) {
	bom, configDesc, err := pushConfig(ctx, target, baseDir, sbomHash, opts.Progress)
	if err != nil {
		return nil, err
	}
	components := sliceutil.Deref(bom.Components)

	plans, err := planLayers(baseDir, components)
	if err != nil {
		return nil, err
	}
	layerDescs, err := pushLayers(ctx, target, plans, opts.Concurrency, opts.Progress)
	if err != nil {
		return nil, err
	}
	desc, err := packManifest(ctx, target, configDesc, layerDescs, bom)
	if err != nil {
		return nil, err
	}

	pkg := pushedPackage{
		desc:       desc,
		components: components,
		layers:     pushedLayers(plans, layerDescs),
	}
	return &pkg, nil
}

// pushConfig pushes the SBOM the build recorded under baseDir for
// sbomHash (see build.RecordManifest) byte for byte, as the package's
// config, returning it parsed and its descriptor.
func pushConfig(ctx context.Context, target oras.Target, baseDir, sbomHash string, progress transfer.ProgressFunc) (*cdx.BOM, ocispec.Descriptor, error) {
	manifestPath := layout.Manifest(baseDir, sbomHash)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("read manifest %s: %w", manifestPath, err)
	}
	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("parse manifest %s: %w", manifestPath, err)
	}

	desc, err := transfer.PushBytes(ctx, target, data, configMediaType(data), "sbom manifest", progress)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("push config: %w", err)
	}
	return bom, desc, nil
}

// packManifest pushes the package manifest of config and layers, in
// order, created when bom says (see createdAnnotation).
func packManifest(ctx context.Context, target oras.Target, config ocispec.Descriptor, layers []ocispec.Descriptor, bom *cdx.BOM) (ocispec.Descriptor, error) {
	packOpts := oras.PackManifestOptions{
		ConfigDescriptor: &config,
		Layers:           layers,
		ManifestAnnotations: map[string]string{
			ocispec.AnnotationCreated: createdAnnotation(bom),
		},
	}
	desc, err := oras.PackManifest(ctx, target, oras.PackManifestVersion1_1, transfer.ArtifactType, packOpts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack manifest: %w", err)
	}
	return desc, nil
}

// createdAnnotation returns the value Push pins the package manifest's
// "org.opencontainers.image.created" annotation to: bom's own
// metadata.timestamp, normalized to UTC RFC 3339, or the Unix epoch if
// the SBOM has none or it doesn't parse.
//
// Left unset, oras.PackManifest stamps the current time instead, giving
// every push of an unchanged package a new manifest digest — and so
// orphaning any signature made on the previous one (see
// internal/signature). A package is identified by its SBOM's content
// hash, so deriving the value from the SBOM keeps the digest stable for
// as long as the package itself is.
func createdAnnotation(bom *cdx.BOM) string {
	created := time.Unix(0, 0)
	if bom.Metadata != nil {
		if t, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err == nil {
			created = t
		}
	}
	return created.UTC().Format(time.RFC3339)
}

// configMediaType picks the OCI config media type matching data's sniffed
// CycloneDX encoding.
func configMediaType(data []byte) string {
	format, err := sbom.DetectFormat(data)
	if err == nil && format == cdx.BOMFileFormatXML {
		return "application/vnd.cyclonedx+xml"
	}
	return "application/vnd.cyclonedx+json"
}
