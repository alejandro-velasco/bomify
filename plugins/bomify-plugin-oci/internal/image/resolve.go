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

	repository := repositoryFor(purl)
	qualifiers := purl.Qualifiers.Map()

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

// Repository returns the registry/repository address purlString's purl
// names — its "repository_url" qualifier, or (namespace/)name if it has
// none — without any tag or digest. Unlike Resolve's full pull
// reference, this is what identifies where the component comes from
// independent of which specific version, which is what the "remote"
// subcommand reports (see plugins/CONTRACT.md).
func Repository(purlString string) (string, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return "", fmt.Errorf("parse purl %q: %w", purlString, err)
	}

	return repositoryFor(purl), nil
}

// repositoryFor returns purl's registry/repository address: its
// "repository_url" qualifier if it has one, otherwise its
// (namespace/)name.
func repositoryFor(purl packageurl.PackageURL) string {
	repository := purl.Name
	if purl.Namespace != "" {
		repository = purl.Namespace + "/" + purl.Name
	}

	if repositoryURL := purl.Qualifiers.Map()["repository_url"]; repositoryURL != "" {
		repository = repositoryURL
	}

	return repository
}
