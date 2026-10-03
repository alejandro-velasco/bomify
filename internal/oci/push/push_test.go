package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/security"
)

var (
	singleFileComponent = cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "single-file",
		Version:    "1.0",
		PackageURL: "pkg:generic/single-file@1.0?download_url=https://example.com/single-file",
	}
	multiFileComponent = cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       "multi-file",
		Version:    "2.0",
		PackageURL: "pkg:oci/multi-file@2.0?repository_url=example.com/multi-file",
	}
)

// TestPushThenPullRoundTrip exercises Push against a real local OCI store
// (no mocking of oras-go), then pulls the result back with the real
// pull.Pull — proving the two independently-written packages agree on
// the artifact format end to end, not just that Push runs without error.
// One component's layer is a single file (as bomify-plugin-generic
// produces); the other's is a directory tree (as bomify-plugin-oci
// produces), exercising Push's tar-the-whole-directory path.
func TestPushThenPullRoundTrip(t *testing.T) {
	baseDir := t.TempDir()

	writeLayer(t, baseDir, singleFileComponent, map[string]string{
		"artifact": "single file contents",
	})
	writeLayer(t, baseDir, multiFileComponent, map[string]string{
		"oci-layout":        `{"imageLayoutVersion":"1.0.0"}`,
		"blobs/sha256/abcd": "fake blob content",
	})

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"single-file","version":"1.0","purl":"pkg:generic/single-file@1.0?download_url=https://example.com/single-file"},` +
		`{"type":"container","name":"multi-file","version":"2.0","purl":"pkg:oci/multi-file@2.0?repository_url=example.com/multi-file"}` +
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

	result, err := Push(ctx, store, tag, baseDir, sbomHash, transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if result.ManifestDigest == "" {
		t.Error("ManifestDigest is empty")
	}
	if len(result.Layers) != 2 {
		t.Fatalf("got %d layers, want 2", len(result.Layers))
	}

	pulledDir := t.TempDir()
	pullResult, err := pull.Pull(ctx, store, tag, pulledDir, transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	gotManifest, err := os.ReadFile(layout.Manifest(pulledDir, pullResult.SBOMHash))
	if err != nil {
		t.Fatalf("read pulled manifest: %v", err)
	}
	if string(gotManifest) != string(sbomBytes) {
		t.Errorf("pulled manifest = %q, want %q", gotManifest, sbomBytes)
	}

	if len(pullResult.Layers) != 2 {
		t.Fatalf("pulled %d layers, want 2", len(pullResult.Layers))
	}

	for _, layer := range pullResult.Layers {
		var component cdx.Component
		switch layer.Purl {
		case singleFileComponent.PackageURL:
			component = singleFileComponent
		case multiFileComponent.PackageURL:
			component = multiFileComponent
		default:
			t.Errorf("unexpected layer purl %q", layer.Purl)
			continue
		}

		// The whole point of unpacking on pull: the layer must land at
		// exactly the path `bomify build` would have used for this
		// component, not some digest-keyed directory of Pull's own
		// invention.
		wantPath := layout.ComponentLayer(pulledDir, component.PackageURL)
		if layer.Path != wantPath {
			t.Errorf("layer %s path = %s, want %s", layer.Purl, layer.Path, wantPath)
		}

		files := readDir(t, layer.Path)
		switch layer.Purl {
		case singleFileComponent.PackageURL:
			if files["artifact"] != "single file contents" {
				t.Errorf("single-file layer content = %v", files)
			}
		case multiFileComponent.PackageURL:
			if files["oci-layout"] != `{"imageLayoutVersion":"1.0.0"}` || files["blobs/sha256/abcd"] != "fake blob content" {
				t.Errorf("multi-file layer content = %v", files)
			}
		}
	}
}

// TestPushAttachesVulnerabilityReportOnMatch covers the "if there is a
// match" half of push/pull carrying vulnerability reports along with a
// package: a component with a local vulnerability report (as `bomify
// security scan` would have written) gets it attached to the package's
// report referrer and restored by pull to that same path, while a component with no
// report carries none — Push/Pull don't invent one.
func TestPushAttachesVulnerabilityReportOnMatch(t *testing.T) {
	baseDir := t.TempDir()

	writeLayer(t, baseDir, singleFileComponent, map[string]string{
		"artifact": "single file contents",
	})
	writeLayer(t, baseDir, multiFileComponent, map[string]string{
		"oci-layout": `{"imageLayoutVersion":"1.0.0"}`,
	})

	reportBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"vulnerabilities":[{"id":"CVE-TEST"}]}`)
	reportPath := layout.Report(baseDir, layout.PurlHash(singleFileComponent.PackageURL), "grype")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		t.Fatalf("mkdir vulnerabilities dir: %v", err)
	}
	if err := os.WriteFile(reportPath, reportBytes, 0o644); err != nil {
		t.Fatalf("write vulnerability report: %v", err)
	}
	// multiFileComponent deliberately gets no report, to prove it's
	// skipped rather than erroring or attaching something empty.

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"single-file","version":"1.0","purl":"pkg:generic/single-file@1.0?download_url=https://example.com/single-file"},` +
		`{"type":"container","name":"multi-file","version":"2.0","purl":"pkg:oci/multi-file@2.0?repository_url=example.com/multi-file"}` +
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

	result, err := Push(ctx, store, tag, baseDir, sbomHash, transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if len(result.Layers) != 2 {
		t.Fatalf("got %d component layers, want 2", len(result.Layers))
	}
	if len(result.VulnerabilityReports) != 1 {
		t.Fatalf("got %d vulnerability reports, want 1", len(result.VulnerabilityReports))
	}
	if got := result.VulnerabilityReports[0].Purl; got != singleFileComponent.PackageURL {
		t.Errorf("attached vulnerability report purl = %q, want %q", got, singleFileComponent.PackageURL)
	}

	pulledDir := t.TempDir()
	pullResult, err := pull.Pull(ctx, store, tag, pulledDir, transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}
	if len(pullResult.Layers) != 2 {
		t.Fatalf("pulled %d component layers, want 2", len(pullResult.Layers))
	}
	if len(pullResult.VulnerabilityReports) != 1 {
		t.Fatalf("pulled %d vulnerability reports, want 1", len(pullResult.VulnerabilityReports))
	}

	report := pullResult.VulnerabilityReports[0]
	if report.Purl != singleFileComponent.PackageURL {
		t.Errorf("pulled vulnerability report purl = %q, want %q", report.Purl, singleFileComponent.PackageURL)
	}
	wantPath := layout.Report(pulledDir, layout.PurlHash(singleFileComponent.PackageURL), "grype")
	if report.Path != wantPath {
		t.Errorf("pulled vulnerability report path = %s, want %s", report.Path, wantPath)
	}
	got, err := os.ReadFile(report.Path)
	if err != nil {
		t.Fatalf("read pulled vulnerability report: %v", err)
	}
	if string(got) != string(reportBytes) {
		t.Errorf("pulled vulnerability report content = %q, want %q", got, reportBytes)
	}

	if _, err := os.Stat(layout.Report(pulledDir, layout.PurlHash(multiFileComponent.PackageURL), "grype")); !os.IsNotExist(err) {
		t.Errorf("multi-file component got a vulnerability report, want none: err = %v", err)
	}
}

func TestPushFailsWithoutLocalLayer(t *testing.T) {
	baseDir := t.TempDir()

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"missing","version":"1.0","purl":"pkg:generic/missing@1.0?download_url=https://example.com/missing"}` +
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

	if _, err := Push(context.Background(), store, "test", baseDir, sbomHash, transfer.Options{Concurrency: 1}); err == nil {
		t.Fatal("Push() error = nil, want error for a component never built locally")
	}
}

func writeLayer(t *testing.T, baseDir string, component cdx.Component, files map[string]string) {
	t.Helper()

	dir := layout.ComponentLayer(baseDir, component.PackageURL)
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// readDir reads every regular file under dir into a map keyed by its
// slash-separated path relative to dir.
func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()

	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		files[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	return files
}

// TestPushAttachesReportsAsReferrer guards where vulnerability reports
// live: never in the package manifest itself, but as the layers of one
// report referrer of it, in the SBOM's component order rather than the
// order their uploads happen to finish in.
func TestPushAttachesReportsAsReferrer(t *testing.T) {
	baseDir := t.TempDir()

	const n = 8
	var components []cdx.Component
	for i := 0; i < n; i++ {
		component := cdx.Component{
			Type:       cdx.ComponentTypeContainer,
			Name:       fmt.Sprintf("c%d", i),
			Version:    "1.0",
			PackageURL: fmt.Sprintf("pkg:generic/c%d@1.0?download_url=https://example.com/c%d", i, i),
		}
		components = append(components, component)
		writeLayer(t, baseDir, component, map[string]string{"artifact": component.Name})
		writeReport(t, baseDir, component, fmt.Sprintf("CVE-%d", i), "2026-01-01T00:00:00Z")
	}
	sbomHash := recordSBOM(t, baseDir, components)

	ctx := context.Background()
	for attempt := 0; attempt < 5; attempt++ {
		store, err := oci.New(t.TempDir())
		if err != nil {
			t.Fatalf("new oci store: %v", err)
		}
		result, err := Push(ctx, store, "test", baseDir, sbomHash, transfer.Options{Concurrency: n})
		if err != nil {
			t.Fatalf("Push() error = %v", err)
		}

		if manifest := fetchManifest(t, store, result.Manifest); len(manifest.Layers) != n {
			t.Fatalf("package manifest has %d layers, want only the %d component layers", len(manifest.Layers), n)
		}

		referrers, err := security.ReportReferrers(ctx, store, result.Manifest)
		if err != nil {
			t.Fatalf("Referrers: %v", err)
		}
		if len(referrers) != 1 || referrers[0].Digest != result.ReportsReferrer.Digest {
			t.Fatalf("got referrers %v, want just %s", referrers, result.ReportsReferrer.Digest)
		}
		if got := referrers[0].Annotations[ocispec.AnnotationCreated]; got != "2026-01-01T00:00:00Z" {
			t.Errorf("referrer created = %q, want the reports' scan time", got)
		}

		reports, err := security.FetchReports(ctx, store, referrers[0])
		if err != nil {
			t.Fatalf("FetchReports: %v", err)
		}
		if len(reports) != n {
			t.Fatalf("referrer carries %d reports, want %d", len(reports), n)
		}
		for i, component := range components {
			if got := reports[i].Annotations[transfer.AnnotationPurl]; got != component.PackageURL {
				t.Errorf("attempt %d: reports[%d] is %q's, want %q's", attempt, i, got, component.PackageURL)
			}
			if got := result.VulnerabilityReports[i].Purl; got != component.PackageURL {
				t.Errorf("attempt %d: Result.VulnerabilityReports[%d] = %q, want %q", attempt, i, got, component.PackageURL)
			}
		}
	}
}

// TestPushRescanKeepsPackageDigest covers the reason reports are
// referrers: pushing again with unchanged reports attaches nothing new,
// and re-scanning then pushing again leaves the package digest — and so
// its signature — untouched, only attaching a newer referrer, which is
// the one pull restores.
func TestPushRescanKeepsPackageDigest(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, singleFileComponent, map[string]string{"artifact": "contents"})
	writeReport(t, baseDir, singleFileComponent, "CVE-OLD", "2026-01-01T00:00:00Z")
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{singleFileComponent})

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	ctx := context.Background()

	var signed []ocispec.Descriptor
	sign := func(_ context.Context, _ oras.Target, _ string, d ocispec.Descriptor) error {
		signed = append(signed, d)
		return nil
	}

	first, err := Push(ctx, store, "test", baseDir, sbomHash, transfer.Options{Concurrency: 1, Sign: sign})
	if err != nil {
		t.Fatalf("first Push() error = %v", err)
	}
	if len(signed) != 2 || signed[0].Digest != first.Manifest.Digest || signed[1].Digest != first.ReportsReferrer.Digest {
		t.Fatalf("signed %v, want the package manifest then its report referrer", signed)
	}

	again, err := Push(ctx, store, "test", baseDir, sbomHash, transfer.Options{Concurrency: 1})
	if err != nil {
		t.Fatalf("second Push() error = %v", err)
	}
	if again.ReportsReferrer.Digest != first.ReportsReferrer.Digest {
		t.Errorf("unchanged reports gave a new referrer %s, want %s again", again.ReportsReferrer.Digest, first.ReportsReferrer.Digest)
	}

	writeReport(t, baseDir, singleFileComponent, "CVE-NEW", "2026-02-01T00:00:00Z")
	rescanned, err := Push(ctx, store, "test", baseDir, sbomHash, transfer.Options{Concurrency: 1})
	if err != nil {
		t.Fatalf("third Push() error = %v", err)
	}
	if rescanned.ManifestDigest != first.ManifestDigest {
		t.Errorf("re-scan changed the package digest from %s to %s", first.ManifestDigest, rescanned.ManifestDigest)
	}

	referrers, err := security.ReportReferrers(ctx, store, first.Manifest)
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(referrers) != 2 || referrers[0].Digest != rescanned.ReportsReferrer.Digest {
		t.Fatalf("got referrers %v, want 2 with the re-scan's first", referrers)
	}

	pulledDir := t.TempDir()
	if _, err := pull.Pull(ctx, store, "test", pulledDir, transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("Pull() error = %v", err)
	}
	got, err := os.ReadFile(layout.Report(pulledDir, layout.PurlHash(singleFileComponent.PackageURL), "grype"))
	if err != nil {
		t.Fatalf("read pulled report: %v", err)
	}
	if !strings.Contains(string(got), "CVE-NEW") {
		t.Errorf("pulled report = %s, want the newest scan's", got)
	}
}

// TestPullSkipsUnverifiedReports covers reports being advisory: a report
// referrer the verifier rejects is skipped, with the reason reported,
// rather than failing a pull whose package itself verified.
func TestPullSkipsUnverifiedReports(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, singleFileComponent, map[string]string{"artifact": "contents"})
	writeReport(t, baseDir, singleFileComponent, "CVE-TEST", "2026-01-01T00:00:00Z")
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{singleFileComponent})

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	ctx := context.Background()
	pushed, err := Push(ctx, store, "test", baseDir, sbomHash, transfer.Options{Concurrency: 1})
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	verify := func(_ context.Context, _ oras.ReadOnlyTarget, _ string, d ocispec.Descriptor) error {
		if d.Digest == pushed.ReportsReferrer.Digest {
			return errors.New("unsigned")
		}
		return nil
	}

	pulledDir := t.TempDir()
	result, err := pull.Pull(ctx, store, "test", pulledDir, transfer.Options{Concurrency: 1, Verify: verify})
	if err != nil {
		t.Fatalf("Pull() error = %v, want the package restored anyway", err)
	}
	if result.ReportsSkipped == nil {
		t.Error("ReportsSkipped = nil, want why the reports were skipped")
	}
	if len(result.VulnerabilityReports) != 0 {
		t.Errorf("restored %d reports, want none", len(result.VulnerabilityReports))
	}
	if _, err := os.Stat(layout.Report(pulledDir, layout.PurlHash(singleFileComponent.PackageURL), "grype")); !os.IsNotExist(err) {
		t.Errorf("unverified report was written: err = %v", err)
	}
}

// writeReport writes component's local vulnerability report, naming one
// vulnerability and dated scannedAt, as `bomify security scan` would.
func writeReport(t *testing.T, baseDir string, component cdx.Component, id, scannedAt string) {
	t.Helper()
	reportPath := layout.Report(baseDir, layout.PurlHash(component.PackageURL), "grype")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		t.Fatalf("mkdir vulnerabilities dir: %v", err)
	}
	report := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"timestamp":%q},"vulnerabilities":[{"id":%q}]}`, scannedAt, id)
	if err := os.WriteFile(reportPath, []byte(report), 0o644); err != nil {
		t.Fatalf("write vulnerability report: %v", err)
	}
}

// recordSBOM records an SBOM describing components under baseDir, as
// `bomify build` would, and returns its hash.
func recordSBOM(t *testing.T, baseDir string, components []cdx.Component) string {
	t.Helper()
	sbomBytes, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components})
	if err != nil {
		t.Fatalf("marshal sbom: %v", err)
	}
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}
	sbomHash, _, err := build.RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	return sbomHash
}

func fetchManifest(t *testing.T, store content.ReadOnlyStorage, desc ocispec.Descriptor) ocispec.Manifest {
	t.Helper()
	data, err := content.FetchAll(context.Background(), store, desc)
	if err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return manifest
}

func TestCreatedAnnotation(t *testing.T) {
	const epoch = "1970-01-01T00:00:00Z"

	tests := []struct {
		name string
		bom  *cdx.BOM
		want string
	}{
		{"no metadata", &cdx.BOM{}, epoch},
		{"no timestamp", &cdx.BOM{Metadata: &cdx.Metadata{}}, epoch},
		{"unparseable timestamp", &cdx.BOM{Metadata: &cdx.Metadata{Timestamp: "yesterday"}}, epoch},
		{"UTC timestamp", &cdx.BOM{Metadata: &cdx.Metadata{Timestamp: "2026-09-28T10:00:00Z"}}, "2026-09-28T10:00:00Z"},
		{"offset normalized to UTC", &cdx.BOM{Metadata: &cdx.Metadata{Timestamp: "2026-09-28T12:00:00+02:00"}}, "2026-09-28T10:00:00Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createdAnnotation(tt.bom); got != tt.want {
				t.Errorf("createdAnnotation() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPushIsDeterministic guards what signing relies on: pushing the
// same package twice yields the same manifest digest, so a signature
// made on one push still applies after the next.
func TestPushIsDeterministic(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, singleFileComponent, map[string]string{"artifact": "single file contents"})

	sbomBytes := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,` +
		`"metadata":{"timestamp":"2026-09-28T10:00:00Z"},"components":[` +
		`{"type":"container","name":"single-file","version":"1.0","purl":"pkg:generic/single-file@1.0?download_url=https://example.com/single-file"}` +
		`]}`)
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o644); err != nil {
		t.Fatalf("write sbom fixture: %v", err)
	}
	sbomHash, _, err := build.RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	ctx := context.Background()
	push := func() (string, ocispec.Manifest) {
		store, err := oci.New(t.TempDir())
		if err != nil {
			t.Fatalf("new oci store: %v", err)
		}
		result, err := Push(ctx, store, "test", baseDir, sbomHash, transfer.Options{Concurrency: 1})
		if err != nil {
			t.Fatalf("Push() error = %v", err)
		}
		desc, err := store.Resolve(ctx, "test")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		data, err := content.FetchAll(ctx, store, desc)
		if err != nil {
			t.Fatalf("fetch manifest: %v", err)
		}
		var manifest ocispec.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatalf("parse manifest: %v", err)
		}
		return result.ManifestDigest, manifest
	}

	first, manifest := push()
	// Sleep past a second boundary, so a wall-clock timestamp would
	// certainly differ between the two pushes.
	time.Sleep(1100 * time.Millisecond)
	second, _ := push()

	if first != second {
		t.Errorf("manifest digests differ across pushes: %s vs %s", first, second)
	}
	if got := manifest.Annotations[ocispec.AnnotationCreated]; got != "2026-09-28T10:00:00Z" {
		t.Errorf("created annotation = %q, want the SBOM's timestamp", got)
	}
}

// TestPushPullKeepsEveryScannersReport pushes a component scanned by two
// scanners: both reports travel in the package's report referrer, each
// annotated with its scanner, and pull restores each to its own path.
func TestPushPullKeepsEveryScannersReport(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, singleFileComponent, map[string]string{"artifact": "single file contents"})

	reports := map[string]string{
		"grype": `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"vulnerabilities":[{"id":"CVE-GRYPE"}]}`,
		"trivy": `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"vulnerabilities":[{"id":"CVE-TRIVY"}]}`,
	}
	for scanner, report := range reports {
		path := layout.Report(baseDir, layout.PurlHash(singleFileComponent.PackageURL), scanner)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(report), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"container","name":"single-file","version":"1.0","purl":"pkg:generic/single-file@1.0?download_url=https://example.com/single-file"}]}`
	if err := os.WriteFile(sbomPath, []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}
	sbomHash, _, err := build.RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	result, err := Push(ctx, store, "test", baseDir, sbomHash, transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if len(result.VulnerabilityReports) != 2 {
		t.Fatalf("attached %d reports, want one per scanner", len(result.VulnerabilityReports))
	}

	layers, err := security.FetchReports(ctx, store, result.ReportsReferrer)
	if err != nil {
		t.Fatal(err)
	}
	var annotated []string
	for _, l := range layers {
		annotated = append(annotated, l.Annotations[security.AnnotationScanPlugin])
	}
	slices.Sort(annotated)
	if !slices.Equal(annotated, []string{"grype", "trivy"}) {
		t.Errorf("report layers' scanners = %v, want grype and trivy", annotated)
	}

	pulledDir := t.TempDir()
	pulled, err := pull.Pull(ctx, store, "test", pulledDir, transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}
	if pulled.ReportsSkipped != nil || len(pulled.VulnerabilityReports) != 2 {
		t.Fatalf("pulled %d reports (skipped: %v), want 2", len(pulled.VulnerabilityReports), pulled.ReportsSkipped)
	}
	for scanner, want := range reports {
		got, err := os.ReadFile(layout.Report(pulledDir, layout.PurlHash(singleFileComponent.PackageURL), scanner))
		if err != nil || string(got) != want {
			t.Errorf("pulled %s report = %q, %v; want %q", scanner, got, err, want)
		}
	}

	// A report layer that doesn't say which scanner produced it can't be
	// restored to anyone's report, so the pull skips the reports rather
	// than guessing.
	manifest := result.Manifest
	blob, err := transfer.PushBytes(ctx, store, []byte(reports["grype"]), transfer.VulnerabilityReportMediaType, "report", nil)
	if err != nil {
		t.Fatal(err)
	}
	blob.Annotations = map[string]string{transfer.AnnotationPurl: singleFileComponent.PackageURL}
	if _, err := transfer.PushReferrer(ctx, store, manifest, transfer.VulnerabilityReportsArtifactType, []ocispec.Descriptor{blob},
		map[string]string{ocispec.AnnotationCreated: "2999-01-01T00:00:00Z"}, "unannotated reports"); err != nil {
		t.Fatal(err)
	}
	skippedDir := t.TempDir()
	pulled, err = pull.Pull(ctx, store, "test", skippedDir, transfer.Options{Concurrency: 2})
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}
	if pulled.ReportsSkipped == nil || len(pulled.VulnerabilityReports) != 0 {
		t.Errorf("pull of an unannotated report: %d restored, skipped %v; want none restored and a reason", len(pulled.VulnerabilityReports), pulled.ReportsSkipped)
	}
}
