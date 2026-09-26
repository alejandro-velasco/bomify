package scan

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
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
func scanImage(provider vulnerability.Provider, purl packageurl.PackageURL) ([]cdx.Vulnerability, error) {
	ref := imageReference(purl)

	cfg := grypePkg.ProviderConfig{
		SyftProviderConfig: grypePkg.SyftProviderConfig{
			SBOMOptions: syft.DefaultCreateSBOMConfig(),
		},
	}

	packages, pkgContext, _, err := grypePkg.Provide(ref, cfg)
	if err != nil {
		return nil, fmt.Errorf("catalog image %q: %w", ref, err)
	}

	return matchPackages(provider, packages, pkgContext, ref)
}
