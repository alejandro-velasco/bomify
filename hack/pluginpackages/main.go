// Command pluginpackages builds the inputs for one bomify plugin package
// per first-party plugin (see plugins/README.md#publishing-a-plugin): it
// cross-compiles each plugin under plugins/ for every platform given and
// writes, per plugin,
//
//	<out>/<kind>/<os>-<arch>/bomify-plugin-<kind>[.exe]
//	<out>/<kind>/sbom.cdx.json
//
// where the SBOM describes each binary as a plugin.PurlType component —
// with its SHA-256, and a distribution reference relative to the SBOM —
// ready for `bomify build`. Run it from the repository root; `make
// plugin-packages` does:
//
//	go run ./hack/pluginpackages -version 1.12.0 -platforms "linux/amd64 windows/amd64" -out dist/plugin-packages
//
// See hack/push-plugin-packages.sh for building and pushing the packages
// themselves.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/alejandro-velasco/bomify/internal/plugin"
)

// aliases lists, per plugin kind, the other kinds its binary also serves:
// each gets its own component in that plugin's package, pointing at the
// same binary, so installing the plugin installs the aliases too.
var aliases = map[string][]string{
	// bomify-plugin-oci handles pkg:docker purls as well.
	"oci": {"docker"},
}

// platform is one GOOS/GOARCH pair to build for.
type platform struct {
	os, arch string
}

// binary is one plugin binary built for a platform.
type binary struct {
	platform platform
	// path is the binary's path relative to its package directory, in
	// forward-slash form (it's used as a URL in the SBOM).
	path string
	// sha256 is its content hash, hex-encoded.
	sha256 string
}

func main() {
	version := flag.String("version", "", "version to build and stamp every plugin package with (required)")
	platforms := flag.String("platforms", "", "space-separated GOOS/GOARCH pairs to build for (required)")
	out := flag.String("out", "", "directory to write one <kind>/ package directory per plugin into (required)")
	flag.Parse()

	if *version == "" || *platforms == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*version, *platforms, *out); err != nil {
		fmt.Fprintln(os.Stderr, "pluginpackages:", err)
		os.Exit(1)
	}
}

func run(version, platformList, out string) error {
	targets, err := parsePlatforms(platformList)
	if err != nil {
		return err
	}

	dirs, err := filepath.Glob(filepath.Join("plugins", plugin.BinaryName("*")))
	if err != nil {
		return err
	}

	for _, dir := range dirs {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		kind := strings.TrimPrefix(filepath.Base(dir), plugin.BinaryName(""))
		if err := buildPackage(dir, kind, version, targets, filepath.Join(out, kind)); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(dir), err)
		}
	}
	return nil
}

// parsePlatforms parses a space-separated list of GOOS/GOARCH pairs.
func parsePlatforms(list string) ([]platform, error) {
	var targets []platform
	for _, field := range strings.Fields(list) {
		goos, goarch, ok := strings.Cut(field, "/")
		if !ok || goos == "" || goarch == "" {
			return nil, fmt.Errorf("invalid platform %q: want GOOS/GOARCH", field)
		}
		targets = append(targets, platform{os: goos, arch: goarch})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no platforms given")
	}
	return targets, nil
}

// buildPackage cross-compiles the plugin in dir for every target into
// pkgDir, replacing whatever was there, and writes its SBOM alongside.
func buildPackage(dir, kind, version string, targets []platform, pkgDir string) error {
	fmt.Println("==>", plugin.BinaryName(kind))

	if err := os.RemoveAll(pkgDir); err != nil {
		return err
	}

	var binaries []binary
	for _, target := range targets {
		fmt.Printf("    %s/%s\n", target.os, target.arch)

		rel := path.Join(target.os+"-"+target.arch, plugin.ExecutableName(kind, target.os))
		dst := filepath.Join(pkgDir, filepath.FromSlash(rel))
		if err := goBuild(dir, target, dst); err != nil {
			return err
		}

		sum, err := sha256File(dst)
		if err != nil {
			return err
		}
		binaries = append(binaries, binary{platform: target, path: rel, sha256: sum})
	}

	return writeSBOM(filepath.Join(pkgDir, "sbom.cdx.json"), kind, version, binaries)
}

// goBuild cross-compiles the plugin in dir for target into dst.
func goBuild(dir string, target platform, dst string) error {
	abs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "build", "-o", abs, "./"+filepath.ToSlash(dir))
	// bomify-plugin-grype and bomify-plugin-sigstore are each their own Go
	// module (see the Makefile's "plugins" target for why), so they build
	// from inside their own directory.
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		cmd = exec.Command("go", "build", "-o", abs, ".")
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "GOOS="+target.os, "GOARCH="+target.arch, "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build for %s/%s: %w", target.os, target.arch, err)
	}
	return nil
}

// sha256File returns path's SHA-256, hex-encoded.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeSBOM writes the SBOM for kind's plugin package to path: one
// plugin.PurlType component per binary, plus one per alias of kind (see
// aliases), each pointing at the same binary.
func writeSBOM(path, kind, version string, binaries []binary) error {
	var components []cdx.Component
	for _, b := range binaries {
		for _, k := range append([]string{kind}, aliases[kind]...) {
			components = append(components, component(k, version, b))
		}
	}

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{Type: cdx.ComponentTypeApplication, Name: plugin.BinaryName(kind), Version: version},
	}
	bom.Components = &components

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := cdx.NewBOMEncoder(f, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	// Keep purl qualifiers readable ("?arch=amd64&os=linux", not "&").
	enc.SetEscapeHTML(false)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_5); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}

// component describes b as kind's plugin binary.
func component(kind, version string, b binary) cdx.Component {
	purl := packageurl.NewPackageURL(plugin.PurlType, "", kind, version, packageurl.QualifiersFromMap(map[string]string{
		"os":   b.platform.os,
		"arch": b.platform.arch,
	}), "")

	return cdx.Component{
		Type:               cdx.ComponentTypeApplication,
		Name:               plugin.BinaryName(kind),
		Version:            version,
		PackageURL:         purl.ToString(),
		Hashes:             &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: b.sha256}},
		ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeDistribution, URL: b.path}},
	}
}
