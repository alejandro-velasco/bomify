// Package scan wraps the grype SDK (github.com/anchore/grype) for
// bomify-plugin-grype: resolving a single purl to one or more packages,
// matching them against grype's vulnerability database, and reporting
// which purl types it can do that for. Most purl types (npm, maven,
// apk, ...) already name a specific package, so grype's own purl
// provider (grype/pkg.Provide) builds one directly from the purl string
// without cataloging anything — no syft needed. "oci"/"docker" purls
// name a whole container image instead, which has no packages of its
// own until something catalogs what's inside it — that one case (see
// image.go) is the one place this plugin uses syft, via grype's own
// syft-backed provider.
package scan

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// id identifies this plugin to grype's DB distribution service (sent as
// part of the User-Agent) and, via installation.DefaultConfig, names the
// on-disk cache directory the vulnerability DB is kept in. Using "grype"
// itself here is deliberate: it's the same cache location the real grype
// CLI uses (installation.DefaultConfig(id).DBRootDir is derived from
// id.Name), so a machine that already has grype installed and its DB
// downloaded doesn't pay for a second, redundant copy.
var id = clio.Identification{Name: "grype", Version: "bomify-plugin-grype"}

// dbConfig returns the distribution and installation configuration Load
// uses to find/update grype's vulnerability database, built from grype's
// own DefaultConfig helpers (see grype/db/v6/distribution and
// grype/db/v6/installation) rather than hand-assembling one field at a
// time.
func dbConfig() (v6dist.Config, v6inst.Config) {
	distCfg := v6dist.DefaultConfig()
	distCfg.ID = id

	installCfg := v6inst.DefaultConfig(id)

	return distCfg, installCfg
}

// Load opens grype's vulnerability database, updating it first if grype
// itself determines an update is due (installation.Config's own
// UpdateCheckMaxFrequency throttles how often that check actually hits
// the network, persisted to disk — so calling Load fresh for every
// component, as "security scan" does, doesn't mean a network round trip
// for every component). The caller must Close the returned provider once
// done.
func Load() (vulnerability.Provider, error) {
	distCfg, installCfg := dbConfig()

	provider, _, err := grype.LoadVulnerabilityDB(distCfg, installCfg, true)
	if err != nil {
		return nil, fmt.Errorf("load vulnerability db: %w", err)
	}

	return provider, nil
}

// DBDirectory returns the directory grype's vulnerability database is
// (or will be) stored in, for diagnostic purposes only.
func DBDirectory() string {
	_, installCfg := dbConfig()
	return installCfg.DBDirectoryPath()
}

// Purl scans the single component purlString identifies, returning
// every CycloneDX vulnerability it's affected by (see toVulnerability
// for the grype-match-to-CycloneDX field mapping). Each vulnerability's
// Affects references purlString itself back — this plugin's only
// responsibility here, per plugins/SECURITY-CONTRACT.md, since a purl
// looked up directly like this names exactly one thing, with nothing
// smaller to attribute a finding to.
//
// An "oci"/"docker" purl is dispatched to scanImage instead, which
// reports Affects differently: see image.go.
func Purl(provider vulnerability.Provider, purlString string) (pluginlib.SecurityResult, error) {
	parsed, err := packageurl.FromString(purlString)
	if err != nil {
		return pluginlib.SecurityResult{}, fmt.Errorf("parse purl %q: %w", purlString, err)
	}

	if parsed.Type == packageurl.TypeOCI || parsed.Type == packageurl.TypeDocker {
		return scanImage(provider, parsed)
	}

	packages, pkgContext, _, err := grypePkg.Provide(purlString, grypePkg.ProviderConfig{})
	if err != nil {
		return pluginlib.SecurityResult{}, fmt.Errorf("resolve purl %q: %w", purlString, err)
	}
	if len(packages) == 0 {
		// A purl grype's provider didn't recognize as belonging to any
		// package ecosystem it can match against (e.g. a "generic"
		// purl) — not an error, just nothing to report. bomify itself
		// should already be filtering these out via SupportedTypes
		// before ever calling Purl, but Purl doesn't rely on that: it
		// degrades to "no vulnerabilities" either way.
		return pluginlib.SecurityResult{}, nil
	}

	matches, err := findMatches(provider, packages, pkgContext)
	if err != nil {
		return pluginlib.SecurityResult{}, fmt.Errorf("find matches for %q: %w", purlString, err)
	}

	vulnerabilities := make([]cdx.Vulnerability, 0, matches.Count())
	for _, m := range matches.Sorted() {
		v := toVulnerability(m)
		v.Affects = &[]cdx.Affects{{Ref: purlString}}
		vulnerabilities = append(vulnerabilities, v)
	}

	return pluginlib.SecurityResult{Vulnerabilities: vulnerabilities}, nil
}

// findMatches runs grype's default matcher set against packages. Shared
// by Purl and scanImage — the only difference between the two is how
// packages and pkgContext were obtained, and how each then turns a match
// into a vulnerability's Affects.
func findMatches(provider vulnerability.Provider, packages []grypePkg.Package, pkgContext grypePkg.Context) (*match.Matches, error) {
	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              matcher.NewDefaultMatchers(matcher.Config{}),
	}

	matches, _, err := vm.FindMatches(packages, pkgContext)
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// SupportedTypes returns every purl type (package-url spec naming, e.g.
// "npm", "golang", "maven" — the same vocabulary plugin.Detect derives
// component purls into on bomify's side) this plugin can scan: every
// type grype.NewDefaultMatchers' default matcher set has a dedicated,
// ecosystem-specific matcher for, plus "oci"/"docker" (scanned by
// cataloging the image with syft first — see image.go).
//
// The ecosystem list is a fixed, hand-maintained table rather than
// something derived from the matcher set at runtime: each grype
// matcher's PackageTypes() reports *syft's* internal type names (e.g.
// "go-module", "java-archive", "python"), not purl type strings, and
// syft's own purl-type-to-Type mapping isn't exposed as a single
// reusable function to invert. The mapping below was verified
// empirically, one purl per matcher, against grype v0.119.0 (see
// grype/matcher/*/matcher.go's PackageTypes() for the syft.Type each
// one declares, and grype/pkg/purl_provider.go for how a purl of that
// type resolves to that same syft.Type).
//
// Deliberately excluded: "generic" (and any purl type not listed here)
// — there's no image or package to catalog or look up for it.
func SupportedTypes() []string {
	return []string{
		packageurl.TypeApk,     // Alpine (grype/matcher/apk)
		packageurl.TypeDebian,  // Debian/Ubuntu (grype/matcher/dpkg)
		packageurl.TypeRPM,     // Fedora/RHEL/etc. (grype/matcher/rpm)
		packageurl.TypeAlpm,    // Arch Linux (grype/matcher/pacman)
		packageurl.TypeBitnami, // Bitnami packages (grype/matcher/bitnami)
		packageurl.TypeNPM,     // Node.js (grype/matcher/javascript)
		packageurl.TypeGolang,  // Go modules (grype/matcher/golang)
		packageurl.TypeMaven,   // Java (grype/matcher/java)
		packageurl.TypePyPi,    // Python (grype/matcher/python)
		packageurl.TypeGem,     // Ruby (grype/matcher/ruby)
		packageurl.TypeCargo,   // Rust (grype/matcher/rust)
		packageurl.TypeNuget,   // .NET (grype/matcher/dotnet)
		packageurl.TypeHex,     // Erlang/Elixir (grype/matcher/hex)
		packageurl.TypeDocker,  // container images, cataloged with syft first (image.go)
		packageurl.TypeOCI,     // same as "oci" — see plugins/README.md on the alias
	}
}
