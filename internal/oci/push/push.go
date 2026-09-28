// Package push publishes a bomify package as an OCI artifact: the
// counterpart to internal/oci/pull. Push packages the SBOM manifest a prior
// `bomify build` recorded (see internal/build) as the artifact's config,
// and each component that SBOM describes as a layer — tarring up whatever
// build pulled for it and annotating the layer with its purl — then pushes
// the whole thing to a registry under a tag.
package push

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
)

// Layer describes one component layer, or one component's vulnerability
// report, that was pushed.
type Layer struct {
	Purl string
	Hash string
}

// Result is the outcome of a successful Push.
type Result struct {
	ManifestDigest string
	Layers         []Layer
	// VulnerabilityReports lists the components whose local vulnerability
	// report (see internal/security) was attached alongside their layer —
	// only ever a subset of Layers, since most components carry none.
	VulnerabilityReports []Layer
}

// Push packages the build recorded under baseDir for sbomHash (see
// build.RecordManifest) as an OCI artifact — the manifest itself as the
// config, and each component it describes as a layer — and pushes it to
// target, tagging the result ref. Any component with a local
// vulnerability report (see internal/security) is pushed an extra layer
// carrying it too (see pushVulnerabilityReport). Layers upload
// concurrently, bounded by concurrency (values less than 1 are treated
// as 1).
func Push(ctx context.Context, target oras.Target, ref, baseDir, sbomHash string, concurrency int, progress transfer.ProgressFunc) (Result, error) {
	if progress == nil {
		progress = transfer.Discard
	}
	if concurrency < 1 {
		concurrency = 1
	}

	manifestPath := build.ManifestPath(baseDir, sbomHash)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return Result{}, fmt.Errorf("read manifest %s: %w", manifestPath, err)
	}

	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return Result{}, fmt.Errorf("parse manifest %s: %w", manifestPath, err)
	}

	configDesc, err := pushBytes(ctx, target, data, configMediaType(data), "sbom manifest", progress)
	if err != nil {
		return Result{}, fmt.Errorf("push config: %w", err)
	}

	var components []cdx.Component
	if bom.Components != nil {
		components = *bom.Components
	}

	layerDescs := make([]ocispec.Descriptor, len(components))
	layers := make([]Layer, len(components))

	var mu sync.Mutex
	var reportDescs []ocispec.Descriptor
	var reports []Layer

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, component := range components {
		i, component := i, component
		g.Go(func() error {
			desc, layer, err := pushComponentLayer(gctx, target, baseDir, component, progress)
			if err != nil {
				return fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
			}
			layerDescs[i] = desc
			layers[i] = layer

			reportDesc, report, attached, err := pushVulnerabilityReport(gctx, target, baseDir, component, progress)
			if err != nil {
				return fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
			}
			if attached {
				mu.Lock()
				reportDescs = append(reportDescs, reportDesc)
				reports = append(reports, report)
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return Result{}, err
	}

	manifestDesc, err := oras.PackManifest(ctx, target, oras.PackManifestVersion1_1, transfer.ArtifactType, oras.PackManifestOptions{
		ConfigDescriptor: &configDesc,
		Layers:           append(layerDescs, reportDescs...),
	})
	if err != nil {
		return Result{}, fmt.Errorf("pack manifest: %w", err)
	}

	if err := target.Tag(ctx, manifestDesc, ref); err != nil {
		return Result{}, fmt.Errorf("tag %s: %w", ref, err)
	}

	return Result{ManifestDigest: manifestDesc.Digest.String(), Layers: layers, VulnerabilityReports: reports}, nil
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

// pushBytes pushes data as a single blob, reporting its progress through
// progress, and returns its descriptor.
func pushBytes(ctx context.Context, target oras.Target, data []byte, mediaType, label string, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	sum := sha256.Sum256(data)
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.NewDigestFromBytes(digest.SHA256, sum[:]),
		Size:      int64(len(data)),
	}

	// A remote registry tolerates re-pushing a blob whose digest it
	// already has, but a local content/oci.Store — as used when Save
	// packages more than one tag sharing a component into the same
	// store — rejects it outright. Checking first makes either target
	// happy, and avoids re-uploading identical content to a registry
	// that already has it.
	if exists, err := target.Exists(ctx, desc); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("check %s: %w", desc.Digest, err)
	} else if exists {
		return desc, nil
	}

	pw := progress(label, desc.Size)
	defer pw.Close()

	if err := target.Push(ctx, desc, io.TeeReader(bytes.NewReader(data), pw)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", desc.Digest, err)
	}

	return desc, nil
}

// pushComponentLayer archives "<baseDir>/layers/<purl-hash>/" — whatever
// `bomify build` pulled for component — into a single tar blob and pushes
// it, annotated with component's purl.
func pushComponentLayer(ctx context.Context, target oras.Target, baseDir string, component cdx.Component, progress transfer.ProgressFunc) (ocispec.Descriptor, Layer, error) {
	purl := component.PackageURL
	dir := filepath.Join(baseDir, "layers", plugin.PurlHash(component))

	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return ocispec.Descriptor{}, Layer{}, fmt.Errorf("no local layer at %s (run `bomify build` first)", dir)
	}

	tarPath, hash, size, err := tarDir(dir)
	if err != nil {
		return ocispec.Descriptor{}, Layer{}, fmt.Errorf("archive %s: %w", dir, err)
	}
	defer os.Remove(tarPath)

	desc := ocispec.Descriptor{
		MediaType: transfer.LayerMediaType,
		Digest:    digest.NewDigestFromEncoded(digest.SHA256, hash),
		Size:      size,
		Annotations: map[string]string{
			ocispec.AnnotationTitle: hash + ".tar",
			transfer.AnnotationPurl: purl,
		},
	}

	// See pushBytes for why this check matters beyond just efficiency:
	// content/oci.Store (unlike a remote registry) rejects a re-push of a
	// digest it already has, which a shared component across more than
	// one tag in the same Save call would otherwise trigger.
	if exists, err := target.Exists(ctx, desc); err != nil {
		return ocispec.Descriptor{}, Layer{}, fmt.Errorf("check layer %s: %w", desc.Digest, err)
	} else if exists {
		return desc, Layer{Purl: purl, Hash: hash}, nil
	}

	f, err := os.Open(tarPath)
	if err != nil {
		return ocispec.Descriptor{}, Layer{}, fmt.Errorf("open %s: %w", tarPath, err)
	}
	defer f.Close()

	label := purl
	if label == "" {
		label = hash
	}
	pw := progress(label, size)
	defer pw.Close()

	if err := target.Push(ctx, desc, io.TeeReader(f, pw)); err != nil {
		return ocispec.Descriptor{}, Layer{}, fmt.Errorf("push layer %s: %w", desc.Digest, err)
	}

	return desc, Layer{Purl: purl, Hash: hash}, nil
}

// pushVulnerabilityReport pushes component's local vulnerability report
// (see internal/security), if one exists at
// "<baseDir>/vulnerabilities/<purl-hash>.json", as an extra layer
// annotated with component's purl, so a later pull can restore it to
// that same path. attached is false, with no error and no blob pushed,
// when component simply has no local report — never scanned, or scanned
// by a plugin that doesn't support its purl type.
func pushVulnerabilityReport(ctx context.Context, target oras.Target, baseDir string, component cdx.Component, progress transfer.ProgressFunc) (desc ocispec.Descriptor, layer Layer, attached bool, err error) {
	purl := component.PackageURL
	purlHash := plugin.PurlHash(component)
	reportPath := security.ReportPath(baseDir, purlHash)

	data, err := os.ReadFile(reportPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ocispec.Descriptor{}, Layer{}, false, nil
		}
		return ocispec.Descriptor{}, Layer{}, false, fmt.Errorf("read vulnerability report %s: %w", reportPath, err)
	}

	label := purl
	if label == "" {
		label = purlHash
	}
	desc, err = pushBytes(ctx, target, data, transfer.VulnerabilityReportMediaType, "vulnerability report: "+label, progress)
	if err != nil {
		return ocispec.Descriptor{}, Layer{}, false, fmt.Errorf("push vulnerability report: %w", err)
	}
	desc.Annotations = map[string]string{
		ocispec.AnnotationTitle: purlHash + ".json",
		transfer.AnnotationPurl: purl,
	}

	return desc, Layer{Purl: purl, Hash: desc.Digest.Encoded()}, true, nil
}

// tarDir archives dir's contents (see transfer.WriteTar) into a new
// temp file (which the caller must remove), returning its path, sha256
// content digest (hex-encoded, unprefixed, matching bomify's on-disk hash
// convention elsewhere), and size.
func tarDir(dir string) (path string, hash string, size int64, err error) {
	tmp, err := os.CreateTemp("", "bomify-push-layer-*.tar")
	if err != nil {
		return "", "", 0, fmt.Errorf("create temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	if err := transfer.WriteTar(dir, io.MultiWriter(tmp, h)); err != nil {
		os.Remove(tmp.Name())
		return "", "", 0, err
	}

	info, err := tmp.Stat()
	if err != nil {
		os.Remove(tmp.Name())
		return "", "", 0, err
	}

	return tmp.Name(), hex.EncodeToString(h.Sum(nil)), info.Size(), nil
}
