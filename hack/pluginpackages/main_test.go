package main

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

func TestParsePlatforms(t *testing.T) {
	got, err := parsePlatforms("linux/amd64  windows/amd64")
	if err != nil {
		t.Fatalf("parsePlatforms() error = %v", err)
	}
	want := []platform{{os: "linux", arch: "amd64"}, {os: "windows", arch: "amd64"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("parsePlatforms() = %v, want %v", got, want)
	}

	for _, bad := range []string{"", "linux", "linux/", "/amd64"} {
		if _, err := parsePlatforms(bad); err == nil {
			t.Errorf("parsePlatforms(%q): want error", bad)
		}
	}
}

// TestWriteSBOMIsWhatBomifyBuilds proves the SBOM writeSBOM produces is
// exactly what bomify itself expects of a plugin package: every component
// parses as a plugin binary for the right kind and platform, and "bomify
// build" finds and verifies each binary from it.
func TestWriteSBOMIsWhatBomifyBuilds(t *testing.T) {
	pkgDir := t.TempDir()

	var binaries []binary
	for _, p := range []platform{{os: "linux", arch: "amd64"}, {os: "windows", arch: "arm64"}} {
		rel := p.os + "-" + p.arch + "/" + plugin.ExecutableName("oci", p.os)
		dst := filepath.Join(pkgDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte("binary for "+p.os), 0o755); err != nil {
			t.Fatal(err)
		}
		sum, err := sha256File(dst)
		if err != nil {
			t.Fatal(err)
		}
		binaries = append(binaries, binary{platform: p, path: rel, sha256: sum})
	}

	sbomPath := filepath.Join(pkgDir, "sbom.cdx.json")
	if err := writeSBOM(sbomPath, "oci", "1.12.0", binaries); err != nil {
		t.Fatalf("writeSBOM() error = %v", err)
	}

	bom, err := sbom.Load(sbomPath)
	if err != nil {
		t.Fatalf("load written SBOM: %v", err)
	}
	if bom.SpecVersion != cdx.SpecVersion1_5 {
		t.Errorf("spec version = %v, want 1.5", bom.SpecVersion)
	}

	// oci's alias means two components per binary: oci and docker.
	want := map[plugin.Binary]bool{
		{Kind: "oci", Version: "1.12.0", OS: "linux", Arch: "amd64"}:      true,
		{Kind: "docker", Version: "1.12.0", OS: "linux", Arch: "amd64"}:   true,
		{Kind: "oci", Version: "1.12.0", OS: "windows", Arch: "arm64"}:    true,
		{Kind: "docker", Version: "1.12.0", OS: "windows", Arch: "arm64"}: true,
	}
	if bom.Components == nil || len(*bom.Components) != len(want) {
		t.Fatalf("components = %v, want %d", bom.Components, len(want))
	}

	for _, c := range *bom.Components {
		b, ok, err := plugin.ParseBinary(c)
		if err != nil || !ok {
			t.Errorf("%s: ParseBinary() = %v, %v, want a plugin binary", c.PackageURL, ok, err)
			continue
		}
		if !want[b] {
			t.Errorf("unexpected component %+v", b)
		}
		delete(want, b)

		if _, err := plugin.CheckBinary(c, pkgDir); err != nil {
			t.Errorf("%s: bomify build would reject it: %v", c.PackageURL, err)
		}
	}
	for b := range want {
		t.Errorf("missing component %+v", b)
	}
}
