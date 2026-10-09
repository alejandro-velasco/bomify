// Package pull restores a bomify package from an OCI artifact: a
// manifest whose config blob is the aggregate SBOM manifest (see
// internal/build) and whose layers are the components that SBOM describes,
// each annotated with the purl it was pulled for, plus whatever
// vulnerability reports (see internal/security) were attached to it as an
// OCI referrer. Pull downloads that manifest's config and layers
// concurrently, and the newest report referrer's reports, laying them out
// in a data directory exactly as `bomify build`/`bomify security scan`
// would have, so packages and tag work against either source.
package pull

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// RestoredLayer describes one component layer, or one component's
// vulnerability report, that was pulled. Path is a directory —
// "<dataDir>/layers/<purl-hash>/", exactly matching what `bomify build`
// would have produced for this component — when the layer was one
// bomify itself pushed (see transfer.LayerMediaType), since Pull unpacks
// that tar automatically. For a vulnerability report (see
// transfer.VulnerabilityReportMediaType), Path is
// "<dataDir>/vulnerabilities/<purl-hash>.json". For any other layer
// format, Path is the single file Pull wrote the blob to verbatim, since
// Pull has no way to know how a foreign format ought to be laid out on
// disk.
type RestoredLayer struct {
	Purl string
	Hash string
	Path string
}

// Result is the outcome of a successful Pull.
type Result struct {
	// ManifestDigest is the digest of the package manifest ref resolved
	// to — the one verified and restored — as "sha256:...".
	ManifestDigest string
	SBOMHash       string
	Layers         []RestoredLayer
	// VulnerabilityReports lists the components whose vulnerability
	// report (see internal/security) the package's newest report
	// referrer carried and Pull restored to
	// "<dataDir>/vulnerabilities/<purl-hash>.json" — only ever a subset
	// of Layers, since most components carry none.
	VulnerabilityReports []RestoredLayer
	// ReportsSkipped, if non-nil, is why Pull restored no vulnerability
	// reports even though the package itself was restored: reports are
	// advisory, so failing to list, verify, or fetch them never fails a
	// pull.
	ReportsSkipped error
}

// Pull resolves ref against target — a manifest whose config is the
// aggregate SBOM manifest and whose layers are pulled components, plus
// (see restoreReports) any vulnerability reports attached to it — and
// writes it into dataDir the same way `bomify
// build` does: the config as "<dataDir>/manifests/<hash>.json", each
// component layer as "<dataDir>/layers/<hash>/<name>" (plus, see
// fetchLayer, that component's own manifest for a layer bomify itself
// pushed, so a later `bomify build` can reuse it instead of re-invoking
// a plugin), and each vulnerability report as
// "<dataDir>/vulnerabilities/<purl-hash>.json", exactly as `bomify
// security scan` itself would have written it. Layers download
// concurrently, bounded by opts.Concurrency. Reports are restored only after every component layer is.
//
// A non-nil verify is called with the manifest ref resolves to before
// anything else is fetched (see transfer.Verifier): if it fails, Pull
// writes nothing to dataDir at all. It's called again with the report
// referrer, whose reports are skipped (see Result.ReportsSkipped), rather
// than the pull failed, if that doesn't pass. Everything fetched afterward is
// fetched by that same verified descriptor — and each blob checked
// against the digest it pins — so ref being re-tagged mid-pull can't
// substitute unverified content. A non-nil opts.VerifyProvenance is
// called with the manifest right after verify, and likewise writes
// nothing if it fails.
//
// A non-nil opts.Scan is called with the package's SBOM once its
// component layers are written, before its reports are restored (see
// transfer.Scanner).
func Pull(ctx context.Context, target oras.ReadOnlyTarget, ref, dataDir string, opts transfer.Options) (Result, error) {
	return PullLayers(ctx, target, ref, dataDir, opts, nil)
}

// PullLayers is Pull, fetching only the component layers and
// vulnerability reports whose purl annotation keep accepts — e.g. just
// the one platform's binary "bomify plugin install" needs out of a
// package carrying every platform's. A nil keep fetches everything, and a
// layer with no purl annotation is always fetched. The SBOM config is
// always fetched in full, whichever layers are skipped.
func PullLayers(ctx context.Context, target oras.ReadOnlyTarget, ref, dataDir string, opts transfer.Options, keep func(purl string) bool) (Result, error) {
	opts = opts.WithDefaults()

	pkg, err := fetchPackage(ctx, target, ref, dataDir, opts)
	if err != nil {
		return Result{}, err
	}
	descs := filterLayers(pkg.manifest.Layers, keep)
	restore := newPackageRestore(target, descs, dataDir, pkg.sbom.bom, opts.Concurrency, opts.Progress)
	layers, err := restore.restoreLayers(ctx)
	if err != nil {
		return Result{}, err
	}
	if opts.Scan != nil {
		if err := opts.Scan(ctx, target, ref, pkg.desc, pkg.sbom.bom); err != nil {
			return Result{}, fmt.Errorf("scan %s: %w", ref, err)
		}
	}

	reports, reportsSkipped := restoreReports(ctx, target, ref, pkg.desc, dataDir, opts.Concurrency, opts.Progress, opts.Verify, keep)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	result := Result{
		ManifestDigest:       pkg.desc.Digest.String(),
		SBOMHash:             pkg.sbom.hash,
		Layers:               layers,
		VulnerabilityReports: reports,
		ReportsSkipped:       reportsSkipped,
	}
	return result, nil
}

// fetchedPackage is the package PullLayers is restoring: its manifest's
// descriptor, the manifest, and its SBOM.
type fetchedPackage struct {
	desc     ocispec.Descriptor
	manifest ocispec.Manifest
	sbom     packageSBOM
}

// fetchPackage resolves ref and verifies it as opts asks, its
// signatures (opts.Verify), then its build provenance
// (opts.VerifyProvenance), before anything is fetched; then fetches its
// manifest and SBOM, recording the SBOM in dataDir as `bomify build`
// would have (see packageSBOM.write).
func fetchPackage(ctx context.Context, target oras.ReadOnlyTarget, ref, dataDir string, opts transfer.Options) (*fetchedPackage, error) {
	desc, err := oras.Resolve(ctx, target, ref, oras.DefaultResolveOptions)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ref, err)
	}
	if opts.Verify != nil {
		if err := opts.Verify(ctx, target, ref, desc); err != nil {
			return nil, fmt.Errorf("verify %s: %w", ref, err)
		}
	}
	if opts.VerifyProvenance != nil {
		if err := opts.VerifyProvenance(ctx, target, ref, desc); err != nil {
			return nil, fmt.Errorf("verify %s: %w", ref, err)
		}
	}

	manifest, err := fetchManifest(ctx, target, desc)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest %s: %w", ref, err)
	}
	config, err := fetchConfig(ctx, target, manifest.Config, opts.Progress)
	if err != nil {
		return nil, fmt.Errorf("fetch config: %w", err)
	}
	if err := config.write(dataDir); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	pkg := fetchedPackage{
		desc:     desc,
		manifest: manifest,
		sbom:     config,
	}
	return &pkg, nil
}

// filterLayers returns the layers of descs to pull: all of them for a nil
// keep, else those whose purl keep accepts, and those naming no purl.
func filterLayers(descs []ocispec.Descriptor, keep func(purl string) bool) []ocispec.Descriptor {
	if keep == nil {
		return descs
	}
	var kept []ocispec.Descriptor
	for _, desc := range descs {
		purl := desc.Annotations[transfer.AnnotationPurl]
		// A layer naming no component has nothing to judge it by.
		if purl == "" || keep(purl) {
			kept = append(kept, desc)
		}
	}
	return kept
}

// restoreReports restores the reports carried by the newest vulnerability
// report referrer of manifest (see security.ReportReferrers) — the one most
// recently scanned — into dataDir, once a non-nil verify accepts that
// referrer. A package with no report referrer restores none, and no
// error; any error is why none were restored.
func restoreReports(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, dataDir string, concurrency int, progress transfer.ProgressFunc, verify transfer.Verifier, keep func(purl string) bool) ([]RestoredLayer, error) {
	referrers, err := security.ReportReferrers(ctx, target, manifest)
	if err != nil {
		return nil, err
	}
	if len(referrers) == 0 {
		return nil, nil
	}
	newest := referrers[0]

	if verify != nil {
		if err := verify(ctx, target, ref, newest); err != nil {
			return nil, fmt.Errorf("verify vulnerability reports %s: %w", newest.Digest, err)
		}
	}

	reportDescs, err := security.FetchReports(ctx, target, newest)
	if err != nil {
		return nil, err
	}
	reportDescs = filterLayers(reportDescs, keep)

	return parallel.Map(ctx, concurrency, reportDescs, func(ctx context.Context, _ int, layerDesc ocispec.Descriptor) (RestoredLayer, error) {
		report, err := fetchVulnerabilityReport(ctx, target, layerDesc, dataDir, progress)
		if err != nil {
			return RestoredLayer{}, fmt.Errorf("fetch vulnerability report %s: %w", layerDesc.Digest, err)
		}
		return report, nil
	})
}

// indexComponentsByPurl indexes bom's components by purl, so fetchLayer
// can look one up by its layer's purl annotation. A nil bom or one with
// no components indexes nothing.
func indexComponentsByPurl(bom *cdx.BOM) map[string]cdx.Component {
	index := map[string]cdx.Component{}
	if bom == nil {
		return index
	}
	for _, c := range sliceutil.Deref(bom.Components) {
		if c.PackageURL != "" {
			index[c.PackageURL] = c
		}
	}
	return index
}

// Manifest resolves ref against target and returns the raw bytes of its
// config blob — the aggregate CycloneDX SBOM manifest — directly from the
// registry. Unlike Pull, it never touches a data directory or any layers:
// it's for inspecting a remote package's manifest, not restoring it
// locally.
func Manifest(ctx context.Context, target oras.ReadOnlyTarget, ref string) ([]byte, error) {
	desc, err := oras.Resolve(ctx, target, ref, oras.DefaultResolveOptions)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ref, err)
	}

	manifest, err := fetchManifest(ctx, target, desc)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest %s: %w", ref, err)
	}

	data, err := content.FetchAll(ctx, target, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("fetch config: %w", err)
	}

	return data, nil
}

func fetchManifest(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor) (ocispec.Manifest, error) {
	data, err := content.FetchAll(ctx, target, desc)
	if err != nil {
		return ocispec.Manifest{}, err
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return ocispec.Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}

	return manifest, nil
}

// fetchConfig downloads desc — the aggregate SBOM manifest — into
// memory, checked against its digest, and parses it, without writing
// anything (see packageSBOM.write).
func fetchConfig(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, progress transfer.ProgressFunc) (packageSBOM, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return packageSBOM{}, err
	}

	pw := progress("sbom manifest", desc.Size)
	defer pw.Close()
	data, err := content.FetchAll(ctx, target, desc)
	if err != nil {
		return packageSBOM{}, err
	}
	pw.Write(data)

	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return packageSBOM{}, fmt.Errorf("parse sbom manifest %s: %w", desc.Digest, err)
	}
	config := packageSBOM{
		data: data,
		hash: hash,
		bom:  bom,
	}
	return config, nil
}

// packageSBOM is a package's SBOM, its config blob: exactly as fetched,
// its hash, which names its record in the data directory, and parsed.
type packageSBOM struct {
	data []byte
	hash string
	bom  *cdx.BOM
}

// write records s byte for byte at "<dataDir>/manifests/<hash>.json", as
// `bomify build` would have.
func (s packageSBOM) write(dataDir string) error {
	return fsutil.WriteFileAtomic(layout.Manifest(dataDir, s.hash), s.data)
}

// fetchLayer writes a layer that isn't one of a component's own (see
// restoreComponent), such as a foreign one, verbatim as a single file,
// since there's no telling how to unpack it.
func fetchLayer(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, dataDir string, progress transfer.ProgressFunc) (RestoredLayer, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return RestoredLayer{}, err
	}

	purl := desc.Annotations[transfer.AnnotationPurl]
	label := transfer.Label(purl, hash)

	destPath := filepath.Join(layout.Layer(dataDir, hash), layerFilename(desc))
	if err := downloadBlob(ctx, target, desc, destPath, label, progress); err != nil {
		return RestoredLayer{}, err
	}

	return RestoredLayer{Purl: purl, Hash: hash, Path: destPath}, nil
}

// fetchVulnerabilityReport downloads desc — one scanner's vulnerability
// report of a component (see transfer.VulnerabilityReportMediaType) —
// straight to "<dataDir>/vulnerabilities/<purl-hash>/<scanner>.json", the
// same path `bomify security scan` itself would have written it to,
// replacing that scanner's report (if any) for that purl. The scanner is
// the layer's own annotation (see security.AnnotationScanPlugin), which it
// must have.
func fetchVulnerabilityReport(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, dataDir string, progress transfer.ProgressFunc) (RestoredLayer, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return RestoredLayer{}, err
	}

	purl := desc.Annotations[transfer.AnnotationPurl]
	if purl == "" {
		return RestoredLayer{}, fmt.Errorf("vulnerability report %s has no %s annotation", desc.Digest, transfer.AnnotationPurl)
	}
	scanner := desc.Annotations[security.AnnotationScanPlugin]
	if err := security.CheckScanner(scanner); err != nil {
		return RestoredLayer{}, fmt.Errorf("vulnerability report %s (%s annotation): %w", desc.Digest, security.AnnotationScanPlugin, err)
	}

	destPath := layout.Report(dataDir, layout.PurlHash(purl), scanner)
	if err := downloadBlob(ctx, target, desc, destPath, purl, progress); err != nil {
		return RestoredLayer{}, err
	}

	return RestoredLayer{Purl: purl, Hash: hash, Path: destPath}, nil
}

// recordComponentManifest writes component's own manifest (matched by
// purl) so a later `bomify build` can reuse it instead of re-invoking a
// plugin. No hash is computed — the SBOM already declares one — and
// nothing is written if purl matches no component in it.
func recordComponentManifest(dataDir string, componentsByPurl map[string]cdx.Component, purl string) error {
	component, ok := componentsByPurl[purl]
	if !ok {
		return nil
	}
	return plugin.WriteManifest(dataDir, component, pluginlib.Hash{})
}

// blobHash returns desc's digest as the hex hash bomify's on-disk layout
// keys files by; bomify only supports sha256 elsewhere (see internal/plugin
// and internal/build), so a differently-hashed artifact is rejected rather
// than silently laid out under a scheme nothing else recognizes.
func blobHash(desc ocispec.Descriptor) (string, error) {
	if desc.Digest.Algorithm() != digest.SHA256 {
		return "", fmt.Errorf("unsupported digest algorithm %q for %s (bomify only supports sha256)", desc.Digest.Algorithm(), desc.Digest)
	}
	return desc.Digest.Encoded(), nil
}

// layerFilename picks the on-disk filename for a layer: its OCI title
// annotation, if that's usable as a plain filename, otherwise its digest.
// The title comes from the registry (or whoever published the artifact),
// so it's treated as untrusted input: anything containing a path separator
// or traversal segment is rejected rather than joined into destPath, which
// would otherwise let a crafted title escape dataDir/layers entirely.
func layerFilename(desc ocispec.Descriptor) string {
	if title := desc.Annotations[ocispec.AnnotationTitle]; transfer.IsSafeFilename(title) {
		return title
	}
	return desc.Digest.Encoded()
}

// downloadBlob streams desc's content from target to destPath, verifying it
// against desc's size and digest as it flows, and reports progress through
// progress. The file lands at destPath only once fully downloaded and
// verified: a failed or interrupted download leaves no partial file there.
func downloadBlob(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, destPath, label string, progress transfer.ProgressFunc) error {
	rc, err := target.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", desc.Digest, err)
	}
	defer rc.Close()

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".pull-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	pw := progress(label, desc.Size)
	defer pw.Close()

	verified := content.NewVerifyReader(rc, desc)
	if _, err := io.Copy(tmp, io.TeeReader(verified, pw)); err != nil {
		tmp.Close()
		return fmt.Errorf("download %s: %w", desc.Digest, err)
	}
	if err := verified.Verify(); err != nil {
		tmp.Close()
		return fmt.Errorf("verify %s: %w", desc.Digest, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmp.Name(), destPath); err != nil {
		return fmt.Errorf("rename to %s: %w", destPath, err)
	}

	return nil
}
