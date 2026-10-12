// Command pluginpackages builds the inputs for one bomify plugin package
// per first-party plugin (see plugins/README.md#publishing-a-plugin) from
// its prebuilt binaries, writing, per plugin under plugins/,
//
//	<out>/<kind>/<os>-<arch>/bomify-plugin-<kind>[.exe]
//	<out>/<kind>/sbom.cdx.json
//
// where the SBOM describes each binary as a plugin.PurlType component —
// with its SHA-256, the contract versions the plugin reports
// (plugin.PropertyContracts), and a distribution reference relative to
// the SBOM — ready for `bomify build`.
//
// It compiles nothing: every plugin's binaries, whatever its language,
// come from -prebuilt, laid out the same way as <prebuilt>/<kind>/... —
// from `make prebuilt-plugins`, or, for a release, built on each
// platform's own runner (see .github/workflows/plugins.yml). Run it
// from the repository root; `make plugin-packages` does:
//
//	go run ./hack/pluginpackages -version 1.12.0 -platforms "linux/amd64 windows/amd64" -prebuilt dist/prebuilt-plugins -out dist/plugin-packages
//
// See hack/push-plugin-packages.sh for building and pushing the packages
// themselves.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// aliases lists, per plugin kind, the other kinds its binary also serves:
// each gets its own component in that plugin's package, pointing at the
// same binary, so installing the plugin installs the aliases too.
var aliases = map[string][]string{
	// bomify-plugin-oci handles pkg:docker purls as well.
	"oci": {"docker"},
}

// platform is one GOOS/GOARCH pair to package for.
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
	version := flag.String("version", "", "version to stamp every plugin package with (required)")
	platforms := flag.String("platforms", "", "space-separated GOOS/GOARCH pairs to package (required)")
	prebuilt := flag.String("prebuilt", "", "directory holding every plugin's binaries, as <kind>/<os>-<arch>/bomify-plugin-<kind>[.exe] (required)")
	out := flag.String("out", "", "directory to write one <kind>/ package directory per plugin into (required)")
	flag.Parse()

	if *version == "" || *platforms == "" || *prebuilt == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*version, *platforms, *prebuilt, *out); err != nil {
		fmt.Fprintln(os.Stderr, "pluginpackages:", err)
		os.Exit(1)
	}
}

// run packages every plugin under plugins/, so one without binaries in
// prebuilt fails rather than going unpublished.
func run(version, platformList, prebuilt, out string) error {
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
		if err := buildPackage(kind, version, targets, filepath.Join(prebuilt, kind), filepath.Join(out, kind)); err != nil {
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

// buildPackage copies kind's binary for every target from prebuiltDir
// into pkgDir, replacing whatever was there, and writes its SBOM
// alongside.
func buildPackage(kind, version string, targets []platform, prebuiltDir, pkgDir string) error {
	fmt.Println("==>", plugin.BinaryName(kind))

	if err := os.RemoveAll(pkgDir); err != nil {
		return err
	}

	var binaries []binary
	for _, target := range targets {
		fmt.Printf("    %s/%s\n", target.os, target.arch)

		rel := binaryPath(kind, target)
		dst := filepath.Join(pkgDir, filepath.FromSlash(rel))
		if err := copyFile(filepath.Join(prebuiltDir, filepath.FromSlash(rel)), dst); err != nil {
			return err
		}

		sum, err := sha256File(dst)
		if err != nil {
			return err
		}
		binaries = append(binaries, binary{platform: target, path: rel, sha256: sum})
	}

	// Asked of this machine's binary, since the others may not run here;
	// every platform's build of the same source speaks the same versions.
	// Its packaged copy, which copyFile makes executable, since a binary
	// downloaded from a CI artifact may not be.
	host := platform{os: runtime.GOOS, arch: runtime.GOARCH}
	contracts, err := contractsOf(filepath.Join(pkgDir, filepath.FromSlash(binaryPath(kind, host))))
	if err != nil {
		return err
	}

	return writeSBOM(filepath.Join(pkgDir, "sbom.cdx.json"), kind, version, contracts, binaries)
}

// binaryPath is where a package holds kind's binary for target, relative
// to its directory, in forward-slash form. -prebuilt holds them the same
// way, under <kind>/.
func binaryPath(kind string, target platform) string {
	return path.Join(target.os+"-"+target.arch, plugin.ExecutableName(kind, target.os))
}

// contractsOf asks the plugin binary at path which contract versions it
// speaks, returning its answer as plugin.PropertyContracts records it.
func contractsOf(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("no binary for this machine to ask for contract versions: %w", err)
	}
	cmd := exec.Command(path, pluginlib.ContractSubcommand)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ask for contract versions: %w", err)
	}

	var result pluginlib.ContractResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return "", fmt.Errorf("parse contract versions: %w", err)
	}
	if len(result.Contracts) == 0 {
		return "", fmt.Errorf("plugin reports no contracts")
	}
	data, err := json.Marshal(result.Contracts)
	return string(data), err
}

// copyFile copies the prebuilt binary src to dst, executable.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("no prebuilt binary: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
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
// aliases), each pointing at the same binary and recording contracts (see
// contractsOf).
func writeSBOM(path, kind, version, contracts string, binaries []binary) error {
	var components []cdx.Component
	for _, b := range binaries {
		for _, k := range append([]string{kind}, aliases[kind]...) {
			components = append(components, component(k, version, contracts, b))
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

// component describes b as kind's plugin binary, speaking contracts.
func component(kind, version, contracts string, b binary) cdx.Component {
	purl := plugin.Purl(kind, version, map[string]string{
		"os":   b.platform.os,
		"arch": b.platform.arch,
	})

	return cdx.Component{
		Type:               cdx.ComponentTypeApplication,
		Name:               plugin.BinaryName(kind),
		Version:            version,
		PackageURL:         purl,
		Hashes:             &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: b.sha256}},
		ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeDistribution, URL: b.path}},
		Properties:         &[]cdx.Property{{Name: plugin.PropertyContracts, Value: contracts}},
	}
}
