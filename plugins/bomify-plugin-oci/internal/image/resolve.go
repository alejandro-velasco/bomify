// Package image resolves component purls to OCI image references and
// transfers them to and from registries via crane.
package image

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// Resolve derives a reference crane can pull or copy from purlString
// (pkg:oci/... or pkg:docker/...), preferring the "tag" qualifier, then a
// digest-shaped version, then a plain tag, and finally the bare repository
// when there is no version at all.
func Resolve(purlString string) (string, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return "", fmt.Errorf("parse purl %q: %w", purlString, err)
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
