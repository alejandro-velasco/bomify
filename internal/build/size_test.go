package build

import (
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestPackageSizeSumsComponentLayers(t *testing.T) {
	baseDir := t.TempDir()

	nginx := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}
	redis := cdx.Component{Name: "redis", Version: "7", PackageURL: "pkg:oci/redis@7"}
	writeComponentFixture(t, baseDir, nginx) // 7 bytes, "content"
	writeComponentFixture(t, baseDir, redis) // 7 bytes, "content"

	sbomHash := writeManifestFixture(t, baseDir, nginx, redis)

	got, err := PackageSize(baseDir, sbomHash)
	if err != nil {
		t.Fatalf("PackageSize() error = %v", err)
	}
	if want := int64(len("content") * 2); got != want {
		t.Errorf("PackageSize() = %d, want %d", got, want)
	}
}

func TestPackageSizeDedupesDuplicatePurls(t *testing.T) {
	baseDir := t.TempDir()

	nginx := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}
	writeComponentFixture(t, baseDir, nginx)

	// The same purl described twice in one SBOM must still only count its
	// (single, shared) layer directory once.
	sbomHash := writeManifestFixture(t, baseDir, nginx, nginx)

	got, err := PackageSize(baseDir, sbomHash)
	if err != nil {
		t.Fatalf("PackageSize() error = %v", err)
	}
	if want := int64(len("content")); got != want {
		t.Errorf("PackageSize() = %d, want %d (deduplicated)", got, want)
	}
}

func TestPackageSizeUnpulledComponentContributesZero(t *testing.T) {
	baseDir := t.TempDir()

	// No writeComponentFixture call for this one — never pulled, so it
	// has no layer directory at all.
	nginx := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}
	sbomHash := writeManifestFixture(t, baseDir, nginx)

	got, err := PackageSize(baseDir, sbomHash)
	if err != nil {
		t.Fatalf("PackageSize() error = %v", err)
	}
	if got != 0 {
		t.Errorf("PackageSize() = %d, want 0 for an unpulled component", got)
	}
}

func TestPackageSizeMissingManifestErrors(t *testing.T) {
	baseDir := t.TempDir()

	if _, err := PackageSize(baseDir, "does-not-exist"); err == nil {
		t.Fatal("PackageSize() error = nil, want an error for a missing manifest")
	}
}

func TestDirSizeMissingDirIsZero(t *testing.T) {
	got, err := dirSize(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("dirSize() error = %v", err)
	}
	if got != 0 {
		t.Errorf("dirSize() = %d, want 0", got)
	}
}

// writeManifestFixture writes components as an SBOM and records it as
// baseDir's build-level manifest (see RecordManifest), returning its
// content hash for PackageSize to look up.
func writeManifestFixture(t *testing.T, baseDir string, components ...cdx.Component) string {
	t.Helper()

	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	writeSBOM(t, sbomPath, components...)

	sbomHash, _, err := RecordManifest(baseDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	return sbomHash
}
