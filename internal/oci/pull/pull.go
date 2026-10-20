// Package pull restores a bomify package from its OCI image index (see
// transfer.Package): the SBOM its SBOM manifest carries as config, each
// component file by file, as the package's files map lays out (see
// transfer.Files), plus whatever vulnerability reports (see
// internal/security) were attached to the index as an OCI referrer. Pull
// downloads components concurrently, and the newest report referrer's
// reports, laying them out in a data directory exactly as `bomify
// build`/`bomify security scan` would have, so packages and tag work
// against either source.
package pull

import (
	"context"
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
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
)

// RestoredComponent is a component that was pulled: its purl, the digest
// of its manifest, and its directory, "<dataDir>/layers/<purl-hash>/",
// exactly what `bomify build` would have written for it.
type RestoredComponent struct {
	Purl   string
	Digest string
	Path   string
}

// RestoredLayer is one component's vulnerability report that was pulled,
// to Path, "<dataDir>/vulnerabilities/<purl-hash>/<scanner>.json".
type RestoredLayer struct {
	Purl string
	Hash string
	Path string
}

// Result is the outcome of a successful Pull.
type Result struct {
	// ManifestDigest is the digest of the package index ref resolved to —
	// the one verified and restored — as "sha256:...".
	ManifestDigest string
	SBOMHash       string
	Components     []RestoredComponent
	// VulnerabilityReports lists the components whose vulnerability
	// report (see internal/security) the package's newest report
	// referrer carried and Pull restored — only ever a subset of
	// Components, since most carry none.
	VulnerabilityReports []RestoredLayer
	// ReportsSkipped, if non-nil, is why Pull restored no vulnerability
	// reports even though the package itself was restored: reports are
	// advisory, so failing to list, verify, or fetch them never fails a
	// pull.
	ReportsSkipped error
}

// Pull resolves ref against target — a bomify package's index (see
// transfer.Package), plus (see restoreReports) any vulnerability reports
// attached to it — and writes it into dataDir the same way `bomify build`
// does: its SBOM as "<dataDir>/manifests/<hash>.json", each component to
// "<dataDir>/layers/<purl-hash>/" (plus that component's own manifest
// record, so a later `bomify build` can reuse it instead of re-invoking a
// plugin), and each vulnerability report as
// "<dataDir>/vulnerabilities/<purl-hash>/<scanner>.json", exactly as
// `bomify security scan` itself would have written it. Components
// download concurrently, bounded by opts.Concurrency. Reports are
// restored only after every component is.
//
// A non-nil opts.Verify is called with the index ref resolves to before
// anything else is fetched (see transfer.Verifier): if it fails, Pull
// writes nothing to dataDir at all. It's called again with the report
// referrer, whose reports are skipped (see Result.ReportsSkipped), rather
// than the pull failed, if that doesn't pass. Everything fetched afterward
// is reached from that same verified descriptor — and each blob checked
// against the digest it pins — so ref being re-tagged mid-pull can't
// substitute unverified content. A non-nil opts.VerifyProvenance is called
// with the index right after opts.Verify, and likewise writes nothing if
// it fails.
//
// A non-nil opts.Scan is called with the package's SBOM once its
// components are written, before its reports are restored (see
// transfer.Scanner).
func Pull(ctx context.Context, target oras.ReadOnlyTarget, ref, dataDir string, opts transfer.Options) (Result, error) {
	return PullComponents(ctx, target, ref, dataDir, opts, nil)
}

// PullComponents is Pull, restoring only the components, and vulnerability
// reports, whose purl keep accepts — e.g. just the one platform's binary
// "bomify plugin install" needs out of a package carrying every
// platform's. A nil keep restores everything. The SBOM is always restored
// in full, whichever components are skipped.
func PullComponents(ctx context.Context, target oras.ReadOnlyTarget, ref, dataDir string, opts transfer.Options, keep func(purl string) bool) (Result, error) {
	opts = opts.WithDefaults()

	pkg, err := fetchPackage(ctx, target, ref, dataDir, opts)
	if err != nil {
		return Result{}, err
	}
	kept := filterByPurl(pkg.components, keep)
	restore := newPackageRestore(target, kept, pkg.files, dataDir, pkg.sbom.bom, opts.Concurrency, opts.Progress)
	components, err := restore.restoreComponents(ctx)
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
		Components:           components,
		VulnerabilityReports: reports,
		ReportsSkipped:       reportsSkipped,
	}
	return result, nil
}

// fetchedPackage is the package PullComponents is restoring: its index's
// descriptor, its component manifests, its files map, and its SBOM.
type fetchedPackage struct {
	desc       ocispec.Descriptor
	components []ocispec.Descriptor
	files      transfer.Files
	sbom       packageSBOM
}

// fetchPackage resolves ref and verifies it as opts asks, its
// signatures (opts.Verify), then its build provenance
// (opts.VerifyProvenance), before anything is fetched; then fetches its
// index, its SBOM, and its files map, recording the SBOM in dataDir as
// `bomify build` would have (see packageSBOM.write).
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

	pkg, err := transfer.FetchPackage(ctx, target, desc)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", ref, err)
	}
	files, err := transfer.FetchFiles(ctx, target, pkg)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", ref, err)
	}
	config, err := fetchConfig(ctx, target, pkg.SBOMManifest.Config, opts.Progress)
	if err != nil {
		return nil, fmt.Errorf("fetch sbom: %w", err)
	}
	if err := config.write(dataDir); err != nil {
		return nil, fmt.Errorf("write sbom: %w", err)
	}

	fetched := fetchedPackage{
		desc:       desc,
		components: pkg.Components,
		files:      files,
		sbom:       config,
	}
	return &fetched, nil
}

// filterByPurl returns the descriptors of descs, component manifests or
// reports, to restore: all of them for a nil keep, else those whose purl
// annotation keep accepts.
func filterByPurl(descs []ocispec.Descriptor, keep func(purl string) bool) []ocispec.Descriptor {
	if keep == nil {
		return descs
	}
	var kept []ocispec.Descriptor
	for _, desc := range descs {
		if keep(desc.Annotations[transfer.AnnotationPurl]) {
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
	reportDescs = filterByPurl(reportDescs, keep)

	return parallel.Map(ctx, concurrency, reportDescs, func(ctx context.Context, _ int, layerDesc ocispec.Descriptor) (RestoredLayer, error) {
		report, err := fetchVulnerabilityReport(ctx, target, layerDesc, dataDir, progress)
		if err != nil {
			return RestoredLayer{}, fmt.Errorf("fetch vulnerability report %s: %w", layerDesc.Digest, err)
		}
		return report, nil
	})
}

// indexComponentsByPurl indexes bom's components by purl, so each
// componentRestore can be given its own by its index entry's purl. A nil
// bom or one with no components indexes nothing.
func indexComponentsByPurl(bom *cdx.BOM) map[string]*cdx.Component {
	index := map[string]*cdx.Component{}
	if bom == nil {
		return index
	}
	components := sliceutil.Deref(bom.Components)
	for i := range components {
		if purl := components[i].PackageURL; purl != "" {
			index[purl] = &components[i]
		}
	}
	return index
}

// Manifest resolves ref against target and returns the raw bytes of the
// package's SBOM — its SBOM manifest's config — directly from the
// registry. Unlike Pull, it never touches a data directory or any
// component: it's for inspecting a remote package's SBOM, not restoring
// it locally.
func Manifest(ctx context.Context, target oras.ReadOnlyTarget, ref string) ([]byte, error) {
	desc, err := oras.Resolve(ctx, target, ref, oras.DefaultResolveOptions)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ref, err)
	}

	pkg, err := transfer.FetchPackage(ctx, target, desc)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", ref, err)
	}

	data, err := content.FetchAll(ctx, target, pkg.SBOMManifest.Config)
	if err != nil {
		return nil, fmt.Errorf("fetch sbom: %w", err)
	}

	return data, nil
}

// fetchConfig downloads desc — the package's SBOM — into memory, checked
// against its digest, and parses it, without writing anything (see
// packageSBOM.write).
func fetchConfig(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, progress transfer.ProgressFunc) (packageSBOM, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return packageSBOM{}, err
	}

	pw := progress("sbom", desc.Size)
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

// packageSBOM is a package's SBOM, its SBOM manifest's config: exactly as
// fetched, its hash, which names its record in the data directory, and
// parsed.
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
	if err := os.MkdirAll(dir, transfer.DirPerm); err != nil {
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
