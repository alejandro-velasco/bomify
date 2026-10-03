// Package plugin is bomify's caller-side orchestration of external
// "bomify-plugin-<kind>" binaries: finding one (Find), running one and
// parsing its JSON result (Invoke), and, for the component plugin contract,
// dispatching SBOM components to one (Pull, Push, Remote, and their --check
// counterparts) with bookkeeping around Pull so each component is fetched
// once. See plugins/contracts/component/v1/CONTRACT.md for the subprocess
// contract a component plugin implements, and pkg/plugin for the Go library a
// plugin author implements it with. The security scanning and signing
// contracts' own calls live with their callers, in internal/security and
// internal/signature, built on Invoke.
//
// Pull is safe to call concurrently, even from separate bomify processes,
// for components that hash to the same directory (e.g. duplicate purls
// within or across SBOMs): if a pid file already names a live process,
// Pull waits for it instead of pulling again; if a manifest already
// exists and nothing is pulling, Pull reuses it; otherwise Pull pulls
// fresh, discarding whatever the directory already contains first —
// a stale pid's leftovers, or (having no manifest at all) a component of
// the same purl restored via `bomify pull` rather than `bomify build` —
// since the plugin contract guarantees the directory starts out empty.
// Whichever of those applies, Pull finishes by verifying the resulting
// hash against the SBOM's, so even a reused result fails if it doesn't
// match this call's component.
//
// CheckPull/CheckPush are the --check counterparts of Pull/Push: cheap,
// stateless queries reporting whether a real Pull/Push would succeed.
package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// binaryPrefix precedes the kind in a plugin's executable name.
const binaryPrefix = "bomify-plugin-"

// PurlType is the purl type of an SBOM component that is itself a plugin
// binary — e.g. "pkg:bomify-plugin/oci@v1.2.0?os=linux&arch=amd64" — as
// opposed to something a plugin fetches. bomify handles these itself (see
// PullBinary) rather than dispatching them to a bomify-plugin-<kind>, and
// "bomify plugin install" installs them (see internal/plugin/install).
const PurlType = "bomify-plugin"

// Purl returns the purl of kind's plugin binary, a PurlType component;
// version and qualifiers (e.g. os, arch) are optional.
func Purl(kind, version string, qualifiers map[string]string) string {
	return packageurl.NewPackageURL(PurlType, "", kind, version, packageurl.QualifiersFromMap(qualifiers), "").ToString()
}

// Detect returns the plugin kind corresponding to the given SBOM
// component's purl type (e.g. "oci" for "pkg:oci/nginx@sha256:abc"),
// which is also the kind passed to BinaryName to locate the plugin
// binary. It requires component to carry a purl, returning an error if it
// doesn't.
func Detect(component cdx.Component) (string, error) {
	if component.PackageURL == "" {
		return "", fmt.Errorf("component %s@%s has no package URL", component.Name, component.Version)
	}

	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		return "", fmt.Errorf("parse package URL: %w", err)
	}

	return purl.Type, nil
}

// BinaryName returns the expected executable name for the plugin handling
// kind, e.g. BinaryName("docker") == "bomify-plugin-docker".
func BinaryName(kind string) string {
	return binaryPrefix + kind
}

// ExecutableName returns the file name BinaryName(kind) is installed
// under on goos: with an ".exe" suffix on Windows, bare everywhere else.
func ExecutableName(kind, goos string) string {
	if goos == "windows" {
		return BinaryName(kind) + ".exe"
	}
	return BinaryName(kind)
}

// ErrNotInstalled is what Find's error wraps when no plugin of the kind
// asked for is installed at all.
var ErrNotInstalled = errors.New("not installed")

// Find resolves the plugin binary for kind in dir (see layout.Plugins) —
// the only place bomify looks for one; PATH is never consulted — that
// bomify will call through contract. Before returning it, Find checks the
// plugin speaks the version of contract bomify needs, the one pkg/plugin
// implements (pluginlib.ContractVersions), asking it with its "contract"
// subcommand once per run. It returns an error wrapping ErrNotInstalled if
// no such plugin is installed there.
func Find(dir, kind string, contract pluginlib.Contract) (string, error) {
	path := filepath.Join(dir, ExecutableName(kind, runtime.GOOS))

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("plugin %q is %w in %s (install it with \"bomify plugin install %s\")", BinaryName(kind), ErrNotInstalled, dir, kind)
		}
		return "", fmt.Errorf("plugin %q: %w", BinaryName(kind), err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("plugin %q: %s is a directory, not an executable", BinaryName(kind), path)
	}

	if err := checkContract(path, kind, info, contract); err != nil {
		return "", err
	}
	return path, nil
}
