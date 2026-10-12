package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if err := writeSBOM(sbomPath, "oci", "1.12.0", `{"component":1}`, binaries); err != nil {
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

		offered, ok, err := plugin.OfferedBy(c)
		if err != nil || !ok {
			t.Errorf("%s: OfferedBy() = %v, %v, want its contract versions", c.PackageURL, ok, err)
		} else if err := plugin.CheckCompatible(c.Name, offered); err != nil {
			t.Errorf("%s: bomify plugin install would refuse it: %v", c.PackageURL, err)
		}
	}
	for b := range want {
		t.Errorf("missing component %+v", b)
	}
}

// buildPlugin builds the Go plugin in plugins/<name>, its own module, for
// this machine to path, as a stand-in prebuilt binary.
func buildPlugin(t *testing.T, name, path string) {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "plugins", name))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", path, ".")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
}

// TestBuildPackage packages a plugin from its prebuilt binaries: copied as
// they are, and its contract versions asked of the one for this machine
// (bomify-plugin-generic, built as a stand-in).
func TestBuildPackage(t *testing.T) {
	host := platform{os: runtime.GOOS, arch: runtime.GOARCH}
	other := platform{os: "plan9", arch: "386"}
	if host == other {
		t.Skip("the stand-in platform is this one")
	}
	prebuilt := filepath.Join(t.TempDir(), "standin")
	hostBinary := filepath.Join(prebuilt, filepath.FromSlash(binaryPath("standin", host)))
	buildPlugin(t, "bomify-plugin-generic", hostBinary)
	// Not executable, as a binary downloaded from a CI artifact isn't.
	if err := os.Chmod(hostBinary, 0o644); err != nil {
		t.Fatal(err)
	}
	otherBinary := filepath.Join(prebuilt, filepath.FromSlash(binaryPath("standin", other)))
	if err := os.MkdirAll(filepath.Dir(otherBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherBinary, []byte("binary for plan9"), 0o755); err != nil {
		t.Fatal(err)
	}

	pkgDir := filepath.Join(t.TempDir(), "standin")
	if err := buildPackage("standin", "1.12.0", []platform{host, other}, prebuilt, pkgDir); err != nil {
		t.Fatalf("buildPackage() error = %v", err)
	}
	for _, target := range []platform{host, other} {
		rel := filepath.FromSlash(binaryPath("standin", target))
		want, _ := sha256File(filepath.Join(prebuilt, rel))
		if got, err := sha256File(filepath.Join(pkgDir, rel)); err != nil || got != want {
			t.Errorf("%s/%s: packaged binary = %s, %v; want the prebuilt one, %s", target.os, target.arch, got, err, want)
		}
	}
	bom, err := sbom.Load(filepath.Join(pkgDir, "sbom.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range *bom.Components {
		if offered, ok, err := plugin.OfferedBy(c); err != nil || !ok || offered["component"] != 1 {
			t.Errorf("%s: contract versions = %v, %v, %v; want the stand-in's", c.PackageURL, offered, ok, err)
		}
	}

	// A platform without a prebuilt binary fails, rather than going
	// unpublished.
	missing := platform{os: "aix", arch: "ppc64"}
	if err := buildPackage("standin", "1.12.0", []platform{host, missing}, prebuilt, pkgDir); err == nil {
		t.Error("buildPackage() succeeded without a binary for every platform")
	}
}

// TestContractsOf asks real plugins, one in this module and one in its
// own, for the contract versions they report.
func TestContractsOf(t *testing.T) {
	for name, want := range map[string]string{
		"bomify-plugin-generic":  `{"component":1}`,
		"bomify-plugin-sigstore": `{"signing":1}`,
	} {
		binary := filepath.Join(t.TempDir(), plugin.ExecutableName(name, runtime.GOOS))
		buildPlugin(t, name, binary)
		got, err := contractsOf(binary)
		if err != nil {
			t.Errorf("contractsOf(%s): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("contractsOf(%s) = %s, want %s", name, got, want)
		}
	}
}
