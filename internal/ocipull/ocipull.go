// Package ocipull restores a bomify package from an OCI artifact: a
// manifest whose config blob is the aggregate SBOM manifest (see
// internal/build) and whose layers are the components that SBOM describes,
// each annotated with the purl it was pulled for. Pull downloads that
// manifest's config and layers concurrently, laying them out in a data
// directory exactly as `bomify build` would have, so packages and tag work
// against either source.
package ocipull

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"bomify/internal/build"
	"bomify/internal/ocitransfer"
)

// AnnotationPurl is the OCI descriptor annotation identifying the purl a
// layer was pulled for.
const AnnotationPurl = ocitransfer.AnnotationPurl

// ProgressFunc is called once per blob (the config, then each layer) before
// it starts downloading, naming it and giving its total size in bytes. The
// returned writer receives the raw bytes as they arrive off the wire, for
// rendering a progress bar, and is closed once that blob's download ends
// (successfully or not). A nil ProgressFunc is fine; Pull renders no
// progress in that case.
type ProgressFunc = ocitransfer.ProgressFunc

// Layer describes one component layer that was pulled.
type Layer struct {
	Purl string
	Hash string
	Path string
}

// Result is the outcome of a successful Pull.
type Result struct {
	SBOMHash string
	Layers   []Layer
}

// Pull resolves ref against target — a manifest whose config is the
// aggregate SBOM manifest and whose layers are pulled components — and
// writes it into dataDir the same way `bomify build` does: the config as
// "<dataDir>/manifests/<hash>.json" and each layer as
// "<dataDir>/layers/<hash>/<name>". Layers download concurrently, bounded
// by concurrency (values less than 1 are treated as 1).
func Pull(ctx context.Context, target oras.ReadOnlyTarget, ref, dataDir string, concurrency int, progress ProgressFunc) (Result, error) {
	if progress == nil {
		progress = ocitransfer.Discard
	}
	if concurrency < 1 {
		concurrency = 1
	}

	desc, err := oras.Resolve(ctx, target, ref, oras.DefaultResolveOptions)
	if err != nil {
		return Result{}, fmt.Errorf("resolve %s: %w", ref, err)
	}

	manifest, err := fetchManifest(ctx, target, desc)
	if err != nil {
		return Result{}, fmt.Errorf("fetch manifest %s: %w", ref, err)
	}

	sbomHash, err := fetchConfig(ctx, target, manifest.Config, dataDir, progress)
	if err != nil {
		return Result{}, fmt.Errorf("fetch config: %w", err)
	}

	layers := make([]Layer, len(manifest.Layers))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, layerDesc := range manifest.Layers {
		i, layerDesc := i, layerDesc
		g.Go(func() error {
			layer, err := fetchLayer(gctx, target, layerDesc, dataDir, progress)
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

	return Result{SBOMHash: sbomHash, Layers: layers}, nil
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

func fetchConfig(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, dataDir string, progress ProgressFunc) (string, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return "", err
	}

	destPath := build.ManifestPath(dataDir, hash)
	if err := downloadBlob(ctx, target, desc, destPath, "sbom manifest", progress); err != nil {
		return "", err
	}

	return hash, nil
}

func fetchLayer(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, dataDir string, progress ProgressFunc) (Layer, error) {
	hash, err := blobHash(desc)
	if err != nil {
		return Layer{}, err
	}

	purl := desc.Annotations[AnnotationPurl]
	destPath := filepath.Join(dataDir, "layers", hash, layerFilename(desc))

	label := purl
	if label == "" {
		label = hash
	}
	if err := downloadBlob(ctx, target, desc, destPath, label, progress); err != nil {
		return Layer{}, err
	}

	return Layer{Purl: purl, Hash: hash, Path: destPath}, nil
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
	if title := desc.Annotations[ocispec.AnnotationTitle]; ocitransfer.IsSafeFilename(title) {
		return title
	}
	return desc.Digest.Encoded()
}

// downloadBlob streams desc's content from target to destPath, verifying it
// against desc's size and digest as it flows, and reports progress through
// progress. The file lands at destPath only once fully downloaded and
// verified: a failed or interrupted download leaves no partial file there.
func downloadBlob(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, destPath, label string, progress ProgressFunc) error {
	rc, err := target.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", desc.Digest, err)
	}
	defer rc.Close()

	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".ocipull-*")
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
