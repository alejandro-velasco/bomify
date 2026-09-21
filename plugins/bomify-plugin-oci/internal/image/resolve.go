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

// Location returns the registry/namespace prefix purlString's purl names
// — its repository address (see repositoryFor) with the component's own
// trailing "/<name>" segment removed, so it's in the same shape Push's
// own --remote expects: destinationReference below appends "/<name>:<tag>"
// onto whatever --remote it's given, so reporting that name back as part
// of "remote" would double it up. This is what the "remote" subcommand
// reports (see plugins/CONTRACT.md): where this component's registry
// lives, not the component's own specific repository within it.
func Location(purlString string) (string, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return "", fmt.Errorf("parse purl %q: %w", purlString, err)
	}

	repository := repositoryFor(purl)
	if repository == purl.Name {
		// No registry/namespace prefix at all (e.g. a bare local name) —
		// nothing left once the name itself is removed.
		return "", nil
	}

	// Only strip a segment-aligned "/<name>" suffix, not just any
	// trailing occurrence of the string purl.Name — a repository like
	// "docker.io/mynginx" must be left alone for purl.Name "nginx",
	// since "mynginx" isn't actually this component's own segment.
	return strings.TrimSuffix(repository, "/"+purl.Name), nil
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
