// Package image resolves CycloneDX components to OCI image references and
// transfers them to and from registries via crane.
package image

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// Resolve derives a reference crane can pull or copy from a component's
// purl (pkg:oci/... or pkg:docker/...), preferring the "tag" qualifier,
// then a digest-shaped version, then a plain tag, and finally falling back
// to "name:version" when there is no usable purl.
func Resolve(component cdx.Component) (string, error) {
	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		if component.Name == "" {
			return "", fmt.Errorf("component has neither a usable purl nor a name: %w", err)
		}
		return component.Name + ":" + versionOrLatest(component), nil
	}

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
		return repository + ":" + qualifiers["tag"], nil
	case strings.HasPrefix(purl.Version, "sha256:"):
		return repository + "@" + purl.Version, nil
	case purl.Version != "":
		return repository + ":" + purl.Version, nil
	default:
		return repository, nil
	}
}

func versionOrLatest(component cdx.Component) string {
	if component.Version == "" {
		return "latest"
	}
	return component.Version
}
