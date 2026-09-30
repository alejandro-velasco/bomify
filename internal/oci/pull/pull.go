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
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// Layer describes one component layer, or one component's vulnerability
// report, that was pulled. Path is a directory —
// "<dataDir>/layers/<purl-hash>/", exactly matching what `bomify build`
// would have produced for this component — when the layer was one
// bomify itself pushed (see transfer.LayerMediaType), since Pull unpacks
// that tar automatically. For a vulnerability report (see
// transfer.VulnerabilityReportMediaType), Path is
// "<dataDir>/vulnerabilities/<purl-hash>.json". For any other layer
// format, Path is the single file Pull wrote the blob to verbatim, since
// Pull has no way to know how a foreign format ought to be laid out on
// disk.
type Layer struct {
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
	Layers         []Layer
	// VulnerabilityReports lists the components whose vulnerability
	// report (see internal/security) the package's newest report
	// referrer carried and Pull restored to
	// "<dataDir>/vulnerabilities/<purl-hash>.json" — only ever a subset
	// of Layers, since most components carry none.
	VulnerabilityReports []Layer
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
// substitute unverified content.
//
// A non-nil opts.Scan is then called with the package's SBOM, fetched
// into memory but not yet written, so a package it rejects also leaves
// nothing behind (see transfer.Scanner).
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
	concurrency, progress := opts.Concurrency, opts.Progress

	desc, err := oras.Resolve(ctx, target, ref, oras.DefaultResolveOptions)
	if err != nil {
		return Result{}, fmt.Errorf("resolve %s: %w", ref, err)
	}

	if opts.Verify != nil {
		if err := opts.Verify(ctx, target, ref, desc); err != nil {
			return Result{}, fmt.Errorf("verify %s: %w", ref, err)
		}
	}

	manifest, err := fetchManifest(ctx, target, desc)
	if err != nil {
		return Result{}, fmt.Errorf("fetch manifest %s: %w", ref, err)
	}

	sbomData, err := fetchConfig(ctx, target, manifest.Config, progress)
	if err != nil {
		return Result{}, fmt.Errorf("fetch config: %w", err)
	}
	if opts.Scan != nil {
		if err := opts.Scan(ctx, ref, sbomData); err != nil {
			return Result{}, fmt.Errorf("scan %s: %w", ref, err)
		}
	}
	sbomHash, bom, err := writeConfig(manifest.Config, sbomData, dataDir)
	if err != nil {
		return Result{}, fmt.Errorf("write config: %w", err)
	}
	componentsByPurl := indexComponentsByPurl(bom)

	componentLayerDescs := filterLayers(manifest.Layers, keep)
	layers := make([]Layer, len(componentLayerDescs))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, layerDesc := range componentLayerDescs {
		i, layerDesc := i, layerDesc
		g.Go(func() error {
			layer, err := fetchLayer(gctx, target, layerDesc, dataDir, componentsByPurl, progress)
			if err != nil {
				return fmt.Errorf("fetch layer %s: %w", layerDesc.Digest, err)
			}
			layers[i] = layer
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return Result{}, err
	}

	result := Result{ManifestDigest: desc.Digest.String(), SBOMHash: sbomHash, Layers: layers}
	result.VulnerabilityReports, result.ReportsSkipped = restoreReports(ctx, target, ref, desc, dataDir, concurrency, progress, opts.Verify, keep)
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	return result, nil
}

// filterLayers returns the layers whose purl annotation keep accepts; a
// nil keep, or a layer with no purl annotation, is always kept.
func filterLayers(descs []ocispec.Descriptor, keep func(purl string) bool) []ocispec.Descriptor {
	var kept []ocispec.Descriptor
	for _, d := range descs {
		if purl := d.Annotations[transfer.AnnotationPurl]; keep != nil && purl != "" && !keep(purl) {
			continue
		}
		kept = append(kept, d)
	}
	return kept
}

// restoreReports restores the reports carried by the newest vulnerability
// report referrer of manifest (see security.Referrers) — the one most
// recently scanned — into dataDir, once a non-nil verify accepts that
// referrer. A package with no report referrer restores none, and no
// error; any error is why none were restored.
func restoreReports(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, dataDir string, concurrency int, progress transfer.ProgressFunc, verify transfer.Verifier, keep func(purl string) bool) ([]Layer, error) {
	referrers, err := security.Referrers(ctx, target, manifest)
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

	reports := make([]Layer, len(reportDescs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, layerDesc := range reportDescs {
		g.Go(func() error {
			report, err := fetchVulnerabilityReport(gctx, target, layerDesc, dataDir, progress)
			if err != nil {
				return fmt.Errorf("fetch vulnerability report %s: %w", layerDesc.Digest, err)
			}
			reports[i] = report
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return reports, nil
}

// indexComponentsByPurl indexes bom's components by purl, so fetchLayer
// can look one up by its layer's purl annotation. A nil bom or one with
// no components indexes nothing.
func indexComponentsByPurl(bom *cdx.BOM) map[string]cdx.Component {
	index := map[string]cdx.Component{}
	if bom == nil || bom.Components == nil {
		return index
	}
	for _, c := range *bom.Components {
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
// memory, checked against its digest, without writing anything: a
// transfer.Scanner gets to see it before anything of the package lands
// in the data directory (see writeConfig).
func fetchConfig(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, progress transfer.ProgressFunc) ([]byte, error) {
	pw := progress("sbom manifest", desc.Size)
	defer pw.Close()

	data, err := content.FetchAll(ctx, target, desc)
	if err != nil {
		return nil, err
	}
	pw.Write(data)
	return data, nil
}

// writeConfig writes data — desc's content, the aggregate SBOM manifest
// — to "<dataDir>/manifests/<hash>.json" and parses it, so callers that
// need to inspect its components (see indexComponentsByPurl) don't have
// to read the file back themselves.
func writeConfig(desc ocispec.Descriptor, data []byte, dataDir string) (string, *cdx.BOM, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return "", nil, err
	}

	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return "", nil, fmt.Errorf("parse sbom manifest %s: %w", desc.Digest, err)
	}

	destPath := layout.Manifest(dataDir, hash)
	if err := fsutil.WriteFileAtomic(destPath, data); err != nil {
		return "", nil, err
	}

	return hash, bom, nil
}

func fetchLayer(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, dataDir string, componentsByPurl map[string]cdx.Component, progress transfer.ProgressFunc) (Layer, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return Layer{}, err
	}

	purl := desc.Annotations[transfer.AnnotationPurl]
	label := transfer.Label(purl, hash)

	// A layer bomify itself pushed is a tar of the exact directory `bomify
	// build` would have produced for this component; unpack it back to
	// that same "layers/<purl-hash>/" path rather than leaving it as an
	// opaque .tar file, so packages/tag/push all see this pull as
	// equivalent to a local build. purl is required to compute that path;
	// without one (shouldn't happen for anything bomify pushed, but this
	// is still someone else's registry data) fall through to the generic
	// verbatim-file path below instead of erroring.
	if desc.MediaType == transfer.LayerMediaType && purl != "" {
		destDir := layout.ComponentLayer(dataDir, purl)

		// downloadAndUntar only ever swaps destDir into place as a whole,
		// complete unpack (see its atomic rename), never a partial one,
		// so existence alone is enough to trust it's already correct —
		// same reasoning build.RecordManifest relies on for its own
		// content-addressed skip.
		if info, err := os.Stat(destDir); err == nil && info.IsDir() {
			if err := recordComponentManifest(dataDir, componentsByPurl, purl); err != nil {
				return Layer{}, err
			}
			return Layer{Purl: purl, Hash: hash, Path: destDir}, nil
		}

		if err := downloadAndUntar(ctx, target, desc, destDir, label, progress); err != nil {
			return Layer{}, err
		}
		if err := recordComponentManifest(dataDir, componentsByPurl, purl); err != nil {
			return Layer{}, err
		}
		return Layer{Purl: purl, Hash: hash, Path: destDir}, nil
	}

	destPath := filepath.Join(layout.Layer(dataDir, hash), layerFilename(desc))
	if err := downloadBlob(ctx, target, desc, destPath, label, progress); err != nil {
		return Layer{}, err
	}

	return Layer{Purl: purl, Hash: hash, Path: destPath}, nil
}

// fetchVulnerabilityReport downloads desc — a component's vulnerability
// report (see transfer.VulnerabilityReportMediaType) — straight to
// "<dataDir>/vulnerabilities/<purl-hash>.json", the same path `bomify
// security scan` itself would have written it to, replacing whatever
// report (if any) was already there for that purl.
func fetchVulnerabilityReport(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, dataDir string, progress transfer.ProgressFunc) (Layer, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return Layer{}, err
	}

	purl := desc.Annotations[transfer.AnnotationPurl]
	if purl == "" {
		return Layer{}, fmt.Errorf("vulnerability report %s has no %s annotation", desc.Digest, transfer.AnnotationPurl)
	}

	destPath := layout.Report(dataDir, layout.PurlHash(purl))
	if err := downloadBlob(ctx, target, desc, destPath, purl, progress); err != nil {
		return Layer{}, err
	}

	return Layer{Purl: purl, Hash: hash, Path: destPath}, nil
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

// downloadAndUntar streams desc's content from target, verifying it
// against desc's size and digest as it flows, and unpacks it as a tar
// archive into destDir (replacing it if it already exists). Everything is
// unpacked into a temporary sibling directory first, then swapped into
// place only once the download is fully verified: a failed or interrupted
// download/unpack leaves destDir untouched.
func downloadAndUntar(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, destDir, label string, progress transfer.ProgressFunc) error {
	rc, err := target.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", desc.Digest, err)
	}
	defer rc.Close()

	parent := filepath.Dir(destDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", parent, err)
	}

	tmpDir, err := os.MkdirTemp(parent, ".pull-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	pw := progress(label, desc.Size)
	defer pw.Close()

	verified := content.NewVerifyReader(rc, desc)
	if err := transfer.ExtractTar(tar.NewReader(io.TeeReader(verified, pw)), tmpDir); err != nil {
		return fmt.Errorf("unpack %s: %w", desc.Digest, err)
	}
	if err := verified.Verify(); err != nil {
		return fmt.Errorf("verify %s: %w", desc.Digest, err)
	}

	if err := os.RemoveAll(destDir); err != nil {
		return fmt.Errorf("remove existing %s: %w", destDir, err)
	}
	if err := os.Rename(tmpDir, destDir); err != nil {
		return fmt.Errorf("rename to %s: %w", destDir, err)
	}

	return nil
}
