package pull

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

func TestPullRejectsNonSHA256Digest(t *testing.T) {
	// A package whose SBOM uses a non-sha256 digest algorithm should be
	// rejected outright: bomify's on-disk layout is keyed by sha256 hex
	// everywhere else (internal/plugin, internal/build), so silently
	// accepting another algorithm here would produce files nothing else
	// could find.
	ctx := context.Background()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	files, err := oras.PushBytes(ctx, store, transfer.FilesMediaType, []byte(`{"components":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	config := ocispec.Descriptor{
		MediaType: "application/vnd.cyclonedx+json",
		Digest:    digest.Digest("sha512:" + hex.EncodeToString(make([]byte, 64))),
		Size:      2,
	}
	sbomManifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: transfer.SBOMArtifactType,
		Config:       config,
		Layers:       []ocispec.Descriptor{files},
	}
	sbomManifestDesc := pushJSON(t, store, ocispec.MediaTypeImageManifest, sbomManifest)
	sbomManifestDesc.ArtifactType = transfer.SBOMArtifactType
	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: transfer.ArtifactType,
		Manifests:    []ocispec.Descriptor{sbomManifestDesc},
	}
	indexDesc := pushJSON(t, store, ocispec.MediaTypeImageIndex, index)
	if err := store.Tag(ctx, indexDesc, "test"); err != nil {
		t.Fatalf("tag index: %v", err)
	}

	_, err = Pull(ctx, store, "test", t.TempDir(), transfer.Options{Concurrency: 1})
	if err == nil || !strings.Contains(err.Error(), "only supports sha256") {
		t.Fatalf("Pull() error = %v, want an error for a non-sha256 digest", err)
	}
}

// pushJSON pushes v, marshalled, into store as a manifest of mediaType,
// returning its descriptor.
func pushJSON(t *testing.T, store *oci.Store, mediaType string, v any) ocispec.Descriptor {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := oras.PushBytes(context.Background(), store, mediaType, data)
	if err != nil {
		t.Fatal(err)
	}
	return desc
}

// TestPullSkipsExistingComponent pulls the same bomify-pushed artifact
// twice into the same dataDir, and confirms the second pull skips
// re-downloading the component's file entirely: no progress call for it,
// and a marker file planted inside its directory after the first pull
// survives the second untouched.
func TestPullSkipsExistingComponent(t *testing.T) {
	component := cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "multi-file",
		Version:    "1.0",
		PackageURL: "pkg:oci/multi-file@1.0?repository_url=example.com/multi-file",
	}

	baseDir := t.TempDir()
	layerDir := layout.ComponentLayer(baseDir, component.PackageURL)
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatalf("mkdir layer dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "a"), []byte("aaa"), 0o644); err != nil {
		t.Fatalf("write layer file: %v", err)
	}

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"multi-file","version":"1.0","purl":"pkg:oci/multi-file@1.0?repository_url=example.com/multi-file"}` +
		`]}`)
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}

	sbomHash, _, err := build.RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	ctx := context.Background()
	const tag = "test"
	if err := build.UpdateRepositories(baseDir, []string{tag}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}
	if _, err := push.Push(ctx, store, tag, baseDir, transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	dataDir := t.TempDir()

	var progressCalls int32
	progress := func(name string, size int64) io.WriteCloser {
		atomic.AddInt32(&progressCalls, 1)
		return transfer.Discard(name, size)
	}

	result1, err := Pull(ctx, store, tag, dataDir, transfer.Options{Concurrency: 1, Progress: progress})
	if err != nil {
		t.Fatalf("first Pull() error = %v", err)
	}
	if len(result1.Components) != 1 {
		t.Fatalf("first pull got %d components, want 1", len(result1.Components))
	}
	if got := atomic.LoadInt32(&progressCalls); got != 2 { // config + the one layer
		t.Fatalf("progress called %d times on first pull, want 2", got)
	}

	marker := filepath.Join(result1.Components[0].Path, "marker")
	if err := os.WriteFile(marker, []byte("still here"), 0o644); err != nil {
		t.Fatalf("plant marker file: %v", err)
	}

	atomic.StoreInt32(&progressCalls, 0)

	result2, err := Pull(ctx, store, tag, dataDir, transfer.Options{Concurrency: 1, Progress: progress})
	if err != nil {
		t.Fatalf("second Pull() error = %v", err)
	}
	if len(result2.Components) != 1 {
		t.Fatalf("second pull got %d components, want 1", len(result2.Components))
	}
	if result2.Components[0].Path != result1.Components[0].Path {
		t.Errorf("second pull component path = %s, want %s", result2.Components[0].Path, result1.Components[0].Path)
	}

	// Only the config should have been re-fetched; the already-restored
	// layer should have been skipped, not re-downloaded.
	if got := atomic.LoadInt32(&progressCalls); got != 1 {
		t.Errorf("progress called %d times on second pull, want 1 (config only, layer skipped)", got)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("marker file gone after second pull, want left in place (skip, not re-restore): %v", err)
	}
}

// pushComponentFixture builds a source data directory containing
// component's layer content, records and pushes it as a package tagged
// tag, and returns the store to pull it back from.
func pushComponentFixture(t *testing.T, component cdx.Component, layerContent []byte) (store *oci.Store, tag string) {
	t.Helper()

	sourceDir := t.TempDir()
	layerDir := layout.ComponentLayer(sourceDir, component.PackageURL)
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatalf("mkdir layer dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "artifact"), layerContent, 0o644); err != nil {
		t.Fatalf("write layer file: %v", err)
	}

	sbomBytes, err := json.Marshal(struct {
		BOMFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		Version     int             `json:"version"`
		Components  []cdx.Component `json:"components"`
	}{"CycloneDX", "1.5", 1, []cdx.Component{component}})
	if err != nil {
		t.Fatalf("marshal sbom fixture: %v", err)
	}
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}

	sbomHash, _, err := build.RecordManifest(sourceDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err = oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}

	tag = "test"
	if err := build.UpdateRepositories(sourceDir, []string{tag}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}
	if _, err := push.Push(context.Background(), store, tag, sourceDir, transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	return store, tag
}

// TestPullRecordsComponentManifest guards against a real gap: `bomify
// pull` used to write only the SBOM-level manifest, never a
// per-component one, so a component restored this way had no way to be
// reused by a later `bomify build` needing the same purl —
// internal/plugin.Pull only reuses a prior pull if a manifest already
// exists for it. Pull now writes that manifest too, preserving whatever
// hash the SBOM already declares (no new hash is computed).
func TestPullRecordsComponentManifest(t *testing.T) {
	component := cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "nginx",
		Version:    "1.27",
		PackageURL: "pkg:oci/nginx@1.27",
		Hashes:     &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "fakehash-nginx-1.27"}},
	}

	store, tag := pushComponentFixture(t, component, []byte("image contents"))

	dataDir := t.TempDir()
	if _, err := Pull(context.Background(), store, tag, dataDir, transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	manifestPath := layout.ComponentManifest(dataDir, component.PackageURL)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read component manifest: %v", err)
	}

	var m plugin.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse component manifest: %v", err)
	}
	if m.Component.PackageURL != component.PackageURL {
		t.Errorf("manifest purl = %q, want %q", m.Component.PackageURL, component.PackageURL)
	}
	if m.Component.Hashes == nil || len(*m.Component.Hashes) != 1 || (*m.Component.Hashes)[0].Value != "fakehash-nginx-1.27" {
		t.Errorf("manifest hashes = %v, want [{SHA-256 fakehash-nginx-1.27}]", m.Component.Hashes)
	}
}

// TestPullBackfillsComponentManifestForPreexistingLayer guards against
// data pulled before this fix: a layer directory with no manifest, which
// is what every prior `bomify pull` produced. Pulling the same package
// again should still write the missing manifest via the
// already-restored fast path, not just skip re-downloading and leave the
// component permanently unreusable by a later `bomify build`.
func TestPullBackfillsComponentManifestForPreexistingLayer(t *testing.T) {
	component := cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "nginx",
		Version:    "1.27",
		PackageURL: "pkg:oci/nginx@1.27",
	}

	store, tag := pushComponentFixture(t, component, []byte("image contents"))

	dataDir := t.TempDir()
	// Simulate a pre-fix pull: the layer directory already exists, but no
	// manifest — planted directly rather than via Pull, so this doesn't
	// depend on the very behavior TestPullRecordsComponentManifest covers.
	preexistingDir := layout.ComponentLayer(dataDir, component.PackageURL)
	if err := os.MkdirAll(preexistingDir, 0o755); err != nil {
		t.Fatalf("mkdir preexisting layer dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(preexistingDir, "artifact"), []byte("image contents"), 0o644); err != nil {
		t.Fatalf("write preexisting layer file: %v", err)
	}

	if _, err := Pull(context.Background(), store, tag, dataDir, transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	manifestPath := layout.ComponentManifest(dataDir, component.PackageURL)
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("component manifest not backfilled for preexisting layer: %v", err)
	}
}

// TestPullFailedVerifyWritesNothing guards Pull's ordering promise: a
// Verifier runs before anything is fetched, so a package that fails
// verification leaves the data directory exactly as it found it.
func TestPullFailedVerifyWritesNothing(t *testing.T) {
	component := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}
	store, tag := pushComponentFixture(t, component, []byte("image contents"))

	var verifiedRef string
	var verifiedDesc ocispec.Descriptor
	verify := func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor) error {
		verifiedRef, verifiedDesc = ref, manifest
		return errors.New("untrusted")
	}

	dataDir := t.TempDir()
	if _, err := Pull(context.Background(), store, tag, dataDir, transfer.Options{Concurrency: 1, Verify: verify}); err == nil {
		t.Fatal("Pull() error = nil, want the verifier's error")
	}

	if verifiedRef != tag {
		t.Errorf("verifier got ref %q, want %q", verifiedRef, tag)
	}
	resolved, err := store.Resolve(context.Background(), tag)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if verifiedDesc.Digest != resolved.Digest {
		t.Errorf("verifier got manifest %s, want %s", verifiedDesc.Digest, resolved.Digest)
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("data dir has %d entries after a failed verify, want none", len(entries))
	}
}

// TestPullFailedScan covers the Scan hook: it sees the package's SBOM
// once its component layers are written, so it can scan their files, and
// rejecting it fails the pull.
func TestPullFailedScan(t *testing.T) {
	component := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}
	store, tag := pushComponentFixture(t, component, []byte("image contents"))

	dataDir := t.TempDir()
	var scannedRef string
	var scannedSBOM *cdx.BOM
	var layerWritten bool
	scan := func(_ context.Context, _ oras.ReadOnlyTarget, ref string, _ ocispec.Descriptor, bom *cdx.BOM) error {
		scannedRef, scannedSBOM = ref, bom
		_, err := os.Stat(layout.ComponentLayer(dataDir, component.PackageURL))
		layerWritten = err == nil
		return errors.New("vulnerable")
	}

	if _, err := Pull(context.Background(), store, tag, dataDir, transfer.Options{Concurrency: 1, Scan: scan}); err == nil {
		t.Fatal("Pull() error = nil, want the scanner's error")
	}
	if scannedRef != tag {
		t.Errorf("scanner got ref %q, want %q", scannedRef, tag)
	}
	if scannedSBOM == nil || scannedSBOM.Components == nil || (*scannedSBOM.Components)[0].PackageURL != component.PackageURL {
		t.Errorf("scanner got SBOM %+v, want the package's", scannedSBOM)
	}
	if !layerWritten {
		t.Error("scanner ran before the component's layer was written")
	}

	// A scanner that passes lets the pull go ahead as usual.
	pass := func(context.Context, oras.ReadOnlyTarget, string, ocispec.Descriptor, *cdx.BOM) error { return nil }
	if _, err := Pull(context.Background(), store, tag, dataDir, transfer.Options{Concurrency: 1, Scan: pass}); err != nil {
		t.Errorf("Pull() with a passing scanner: %v", err)
	}
}
