package scan

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// imageReference derives a reference syft's own source resolution (see
// getSource in grype/pkg/syft_provider.go) can pull or open from purl,
// preferring the "tag" qualifier, then a digest-shaped version, then a
// plain tag, and finally the bare repository when there is no version at
// all. This mirrors bomify-plugin-oci's own internal/image.Resolve
// exactly — duplicated rather than imported since that package is
// internal to bomify-plugin-oci and this plugin is its own module with
// no path back to it.
func imageReference(purl packageurl.PackageURL) string {
	repository := purl.Name
	if purl.Namespace != "" {
		repository = purl.Namespace + "/" + purl.Name
	}

	qualifiers := purl.Qualifiers.Map()
	if repositoryURL := qualifiers["repository_url"]; repositoryURL != "" {
		repository = repositoryURL
	}

	switch {
	case qualifiers["tag"] != "":
		return repository + ":" + qualifiers["tag"]
	case strings.HasPrefix(purl.Version, "sha256:"):
		return repository + "@" + purl.Version
	case purl.Version != "":
		return repository + ":" + purl.Version
	default:
		return repository
	}
}

// scanImage catalogs the container image purl refers to with syft (via
// grype's own syft-backed provider — see grype/pkg/syft_provider.go,
// which syft.GetSource/syft.CreateSBOM under the hood, the same code
// path `grype <image>` itself uses) and matches every package it finds
// against provider. syft.DefaultCreateSBOMConfig() is required here:
// grype's provider treats a nil/zero SBOMOptions as "this input isn't an
// image" and declines to handle it at all.
//
// Image pulling uses syft's own default source resolution and registry
// authentication (the local Docker/Podman daemon if present, otherwise
// the registry directly via the same keychain `docker login`/`crane
// auth login` populate) — the same defaults the standalone `grype`/
// `syft` CLIs use, not bomify's own `bomify login` credential store,
// which only `bomify-plugin-oci` reads.
func scanImage(provider vulnerability.Provider, purl packageurl.PackageURL) (pluginlib.SecurityResult, error) {
	ref := imageReference(purl)

	cfg := grypePkg.ProviderConfig{
		SyftProviderConfig: grypePkg.SyftProviderConfig{
			SBOMOptions: syft.DefaultCreateSBOMConfig(),
		},
	}

	packages, pkgContext, _, err := grypePkg.Provide(ref, cfg)
	if err != nil {
		return pluginlib.SecurityResult{}, fmt.Errorf("catalog image %q: %w", ref, err)
	}

	matches, err := findMatches(provider, packages, pkgContext)
	if err != nil {
		return pluginlib.SecurityResult{}, fmt.Errorf("find matches for %q: %w", ref, err)
	}

	return buildImageResult(packages, matches), nil
}

// buildImageResult reports every package syft found while cataloging the
// image as a nested CycloneDX component (see toComponent), and every
// match as a vulnerability whose Affects references the specific
// package(s) it was matched against — never the image itself, since only
// this plugin knows which package inside it is actually affected. The
// same vulnerability matched against more than one package (common: the
// same CVE often affects several packages in one image) is folded into a
// single entry naming every affected package, rather than duplicated.
func buildImageResult(packages []grypePkg.Package, matches *match.Matches) pluginlib.SecurityResult {
	components := make([]cdx.Component, 0, len(packages))
	for _, p := range packages {
		components = append(components, toComponent(p))
	}

	vulnerabilities := make([]cdx.Vulnerability, 0, matches.Count())
	byRef := map[string]int{}

	for _, m := range matches.Sorted() {
		v := toVulnerability(m)
		affectedRef := packageRef(m.Package)

		if v.BOMRef != "" {
			if i, ok := byRef[v.BOMRef]; ok {
				vulnerabilities[i].Affects = appendAffectedRef(vulnerabilities[i].Affects, affectedRef)
				continue
			}
			byRef[v.BOMRef] = len(vulnerabilities)
		}

		v.Affects = appendAffectedRef(nil, affectedRef)
		vulnerabilities = append(vulnerabilities, v)
	}

	return pluginlib.SecurityResult{Vulnerabilities: vulnerabilities, Components: components}
}

// toComponent converts a package grype/syft found while cataloging an
// image into the CycloneDX component bomify embeds under the image's own
// component.
func toComponent(p grypePkg.Package) cdx.Component {
	return cdx.Component{
		BOMRef:     packageRef(p),
		Type:       cdx.ComponentTypeLibrary,
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
	}
}

// packageRef returns the reference toComponent and buildImageResult's
// Affects entries should name p by: its purl if it has one (true for
// nearly every package grype matches), falling back to grype's own
// internally-assigned package ID otherwise.
func packageRef(p grypePkg.Package) string {
	if p.PURL != "" {
		return p.PURL
	}
	return string(p.ID)
}

// appendAffectedRef returns affects with ref appended, unless it's
// already present.
func appendAffectedRef(affects *[]cdx.Affects, ref string) *[]cdx.Affects {
	var list []cdx.Affects
	if affects != nil {
		list = *affects
	}
	for _, a := range list {
		if a.Ref == ref {
			return &list
		}
	}
	list = append(list, cdx.Affects{Ref: ref})
	return &list
}
