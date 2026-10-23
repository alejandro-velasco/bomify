// Package push publishes a bomify package as an OCI image index: the
// counterpart to internal/oci/pull. Push packages each component a prior
// `bomify build` pulled as a manifest of its own, in its kind's registry
// format where its plugin packs one (see transfer.Packer), as ModelPack for
// a model, or else in bomify's own (see transfer.ComponentArtifactType);
// the SBOM that build recorded (see internal/build) as the config of one
// more manifest, which also carries what pull needs to restore the
// components file by file (see transfer.Files); and an index of them all,
// which it pushes to a registry under a tag.
package push

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
)

// PushedComponent is a component Push put in the package's index: its
// purl, and its manifest.
type PushedComponent struct {
	Purl     string
	Manifest ocispec.Descriptor
}

// PushedLayer describes one component's vulnerability report that was
// pushed.
type PushedLayer struct {
	Purl string
	Hash string
}

// Result is the outcome of a successful Push.
type Result struct {
	// Manifest is the pushed package's index, which ref now points at.
	Manifest       ocispec.Descriptor
	ManifestDigest string
	// Components are the components in the index, in the SBOM's order.
	Components []PushedComponent
	// TaggedComponents are where each was tagged in a repository of its
	// own, if opts.ComponentTarget was set.
	TaggedComponents []TaggedComponent
	// VulnerabilityReports lists the components whose local vulnerability
	// report (see internal/security) was attached to the package, as
	// layers of ReportsReferrer — only ever a subset of Components, since
	// most carry none.
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

// Push packages the build ref is a local tag of in baseDir (see
// build.ResolveTag) as an OCI image index — a manifest of the SBOM,
// and one of each component it describes (see pushPackage) — and pushes it
// to target, tagging the index ref. Every component's local vulnerability
// report (see internal/security), if any, is attached as one OCI referrer
// of the index rather than as part of it (see security.Attach), so
// re-scanning never changes the package's digest. Blobs upload
// concurrently, bounded by opts.Concurrency. Each of opts.Attach is
// attached as a referrer of its own too (see transfer.Attach), and so is
// the build's provenance, if it recorded any, signed by opts.Attest if set
// (see provenance.Attach). A non-nil opts.Sign is called with the index,
// and then with every other referrer this push attached, before ref is
// tagged (see transfer.Signer), so a signing failure never leaves ref
// pointing at an unsigned package.
//
// With a non-nil opts.ComponentTarget, each component's manifest is also
// tagged in a repository of its own beside ref's, where its own tools pull
// it by name (see componentSiteOf and componentTagger), and signed there
// too, before ref is tagged. The index names where (see
// transfer.AnnotationComponentReference) either way, for every component
// that has a site: one that can't be placed fails only a push that tags
// (see planSites).
func Push(ctx context.Context, target oras.Target, ref, baseDir string, opts transfer.Options) (Result, error) {
	opts = opts.WithDefaults()
	sbomHash, err := build.ResolveTag(baseDir, ref)
	if err != nil {
		return Result{}, err
	}

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
	reportsReferrer, reports, err := attacher.attachReports(ctx, baseDir, pkg.sbomComponents)
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

	var tagged []TaggedComponent
	if opts.ComponentTarget != nil {
		tagger := componentTagger{
			source: target,
			ref:    ref,
			opts:   opts,
		}
		if tagged, err = tagger.tagAll(ctx, pkg.sites); err != nil {
			return Result{}, err
		}
	}

	if err := target.Tag(ctx, pkg.desc, ref); err != nil {
		return Result{}, fmt.Errorf("tag %s: %w", ref, err)
	}

	result := Result{
		Manifest:             pkg.desc,
		ManifestDigest:       pkg.desc.Digest.String(),
		Components:           pkg.components,
		TaggedComponents:     tagged,
		VulnerabilityReports: reports,
		ReportsReferrer:      reportsReferrer,
		Attached:             attached,
		Provenance:           provenanceReferrer,
	}
	return result, nil
}

// pushedPackage is the package Push has pushed, but not yet tagged: its
// index's descriptor, the components its SBOM describes, and those in
// the index.
type pushedPackage struct {
	desc           ocispec.Descriptor
	sbomComponents []cdx.Component
	components     []PushedComponent
	// sites are where each component is tagged beside the package.
	sites []*componentSitePlan
}

// pushPackage pushes the build recorded under baseDir for sbomHash: each
// component's manifest (see planComponent), its blobs up to
// opts.Concurrency at once, then the SBOM manifest (see pushSBOM), its
// deployments, if it has any (see pushDeployments), and then the index
// of them all.
func pushPackage(ctx context.Context, target oras.Target, baseDir, sbomHash string, opts transfer.Options) (*pushedPackage, error) {
	sbomData, bom, err := readSBOM(baseDir, sbomHash)
	if err != nil {
		return nil, err
	}
	sbomComponents := sliceutil.Deref(bom.Components)
	components := uniqueComponents(sbomComponents)

	plans, err := planComponents(ctx, baseDir, components, opts)
	if err != nil {
		return nil, err
	}
	manifests, err := pushComponents(ctx, target, plans, opts)
	if err != nil {
		return nil, err
	}
	sbomManifest, err := pushSBOM(ctx, target, sbomData, manifests, opts.Progress)
	if err != nil {
		return nil, err
	}

	sites, err := planSites(components, manifests)
	if err != nil && opts.ComponentTarget != nil {
		return nil, err
	}
	references := map[string]string{}
	for _, site := range sites {
		for _, purl := range site.purls {
			references[purl] = site.site.reference()
		}
	}

	entries := []ocispec.Descriptor{sbomManifest}
	pushed := make([]PushedComponent, 0, len(components))
	for index, component := range components {
		entry := manifests[index].desc
		entry.Annotations = map[string]string{
			transfer.AnnotationPurl: component.PackageURL,
		}
		if reference, ok := references[component.PackageURL]; ok {
			entry.Annotations[transfer.AnnotationComponentReference] = reference
		}
		entries = append(entries, entry)
		pushedComponent := PushedComponent{
			Purl:     component.PackageURL,
			Manifest: manifests[index].desc,
		}
		pushed = append(pushed, pushedComponent)
	}
	deployments, hasDeployments, err := pushDeployments(ctx, target, baseDir, sbomHash, opts.Progress)
	if err != nil {
		return nil, err
	}
	if hasDeployments {
		entries = append(entries, deployments)
	}
	desc, err := pushIndex(ctx, target, entries, bom)
	if err != nil {
		return nil, err
	}

	pkg := pushedPackage{
		desc:           desc,
		sbomComponents: sbomComponents,
		components:     pushed,
		sites:          sites,
	}
	return &pkg, nil
}

// uniqueComponents returns components without any whose purl an earlier
// one has: the index holds each component once.
func uniqueComponents(components []cdx.Component) []cdx.Component {
	seen := map[string]bool{}
	var unique []cdx.Component
	for _, component := range components {
		if seen[component.PackageURL] {
			continue
		}
		seen[component.PackageURL] = true
		unique = append(unique, component)
	}
	return unique
}

// pushComponents pushes each of plans' blobs, every component's at once,
// up to opts.Concurrency at a time (see pushLayers), and then each
// component's manifest, returning them in plans' order.
//
// It puts every component's layers in one list, one after another, so they
// all upload at once, and records in starts where each component's begin
// in it, then the list's end, so component i's are
// layers[starts[i]:starts[i+1]]. For components A, B, and C of 3, 0, and 2
// layers:
//
//	layers: A0 A1 A2 C0 C1
//	starts: 0, 3, 3, 5    (A: 0..3, B: 3..3, none, C: 3..5)
//
// pushLayers returns descs in layers' order, so each component's
// descriptors are at the same indices.
func pushComponents(ctx context.Context, target oras.Target, plans []componentPlan, opts transfer.Options) ([]componentManifest, error) {
	var layers []blobPlan
	starts := make([]int, 0, len(plans)+1)
	for _, plan := range plans {
		starts = append(starts, len(layers))
		layers = append(layers, plan.layers()...)
	}
	starts = append(starts, len(layers))

	descs, err := pushLayers(ctx, target, layers, opts.Concurrency, opts.Progress)
	if err != nil {
		return nil, err
	}

	manifests := make([]componentManifest, 0, len(plans))
	for index, plan := range plans {
		first, end := starts[index], starts[index+1]
		componentDescs := descs[first:end]
		manifest, err := plan.pushManifest(ctx, target, componentDescs, opts)
		if err != nil {
			return nil, err
		}
		manifests = append(manifests, manifest)
	}
	return manifests, nil
}

// pushSBOM pushes the package's SBOM, data, as the SBOM manifest: data,
// byte for byte, as its config, and as its layers the files map of
// manifests (see transfer.Files), then the extra files it names, returning
// its descriptor for the index. It comes after every component, whose
// files the map names.
func pushSBOM(ctx context.Context, target oras.Target, data []byte, manifests []componentManifest, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	config, err := transfer.PushBytes(ctx, target, data, configMediaType(data), "sbom", progress)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push SBOM: %w", err)
	}

	files := transfer.Files{Components: []transfer.ComponentFiles{}}
	var extras []ocispec.Descriptor
	for _, manifest := range manifests {
		files.Components = append(files.Components, manifest.files)
		extras = append(extras, manifest.extras...)
	}
	filesData, err := json.Marshal(files)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	filesDesc, err := transfer.PushBytes(ctx, target, filesData, transfer.FilesMediaType, "files map", progress)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push files map: %w", err)
	}

	layers := append([]ocispec.Descriptor{filesDesc}, extras...)
	return pushManifest(ctx, target, transfer.SBOMArtifactType, config, layers, nil)
}

// pushIndex pushes the package's index of entries, its SBOM manifest and
// then its components', created when bom says (see createdAnnotation).
func pushIndex(ctx context.Context, target oras.Target, entries []ocispec.Descriptor, bom *cdx.BOM) (ocispec.Descriptor, error) {
	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: transfer.ArtifactType,
		Manifests:    entries,
		Annotations: map[string]string{
			ocispec.AnnotationCreated: createdAnnotation(bom),
		},
	}
	data, err := json.Marshal(index)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc, err := transfer.PushBytes(ctx, target, data, ocispec.MediaTypeImageIndex, "package index", nil)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push index: %w", err)
	}
	desc.ArtifactType = transfer.ArtifactType
	return desc, nil
}

// readSBOM reads the SBOM the build recorded under baseDir for sbomHash
// (see build.RecordManifest), returning it as it is, which pushSBOM
// pushes byte for byte, and parsed.
func readSBOM(baseDir, sbomHash string) ([]byte, *cdx.BOM, error) {
	path := layout.Manifest(baseDir, sbomHash)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read SBOM %s: %w", path, err)
	}
	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SBOM %s: %w", path, err)
	}
	return data, bom, nil
}

// createdAnnotation returns the value Push pins the package index's
// "org.opencontainers.image.created" annotation to: bom's own
// metadata.timestamp, normalized to UTC RFC 3339, or the Unix epoch if
// the SBOM has none or it doesn't parse.
//
// A package is identified by its SBOM's content hash, so deriving the
// value from the SBOM, rather than the time of the push, keeps the
// index's digest stable for as long as the package itself is, and so any
// signature made on it valid (see internal/signature).
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
