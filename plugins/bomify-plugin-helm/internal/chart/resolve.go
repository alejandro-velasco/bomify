// Package chart resolves component purls to Helm chart references and
// pulls/pushes them using the Helm SDK (helm.sh/helm/v3).
package chart

import (
	"fmt"

	"github.com/package-url/packageurl-go"
	"helm.sh/helm/v3/pkg/registry"
)

// Ref identifies a chart and where its purl says to find it.
type Ref struct {
	Name string
	// Version is the chart version, e.g. "1.2.3".
	Version string
	// RepositoryURL is where the purl says the chart lives: either a
	// classic HTTP(S) chart repository base URL, or an "oci://" registry
	// reference, per OCI is set.
	RepositoryURL string
	// OCI is true when RepositoryURL is an OCI registry reference rather
	// than a classic HTTP(S) chart repository.
	OCI bool
}

// Resolve parses purlString (pkg:helm/<name>@<version>?repository_url=...)
// into a Ref.
func Resolve(purlString string) (Ref, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return Ref{}, fmt.Errorf("parse purl %q: %w", purlString, err)
	}

	repositoryURL := purl.Qualifiers.Map()["repository_url"]
	if repositoryURL == "" {
		return Ref{}, fmt.Errorf("purl %q has no repository_url qualifier", purlString)
	}

	if purl.Version == "" {
		return Ref{}, fmt.Errorf("purl %q has no version", purlString)
	}

	return Ref{
		Name:          purl.Name,
		Version:       purl.Version,
		RepositoryURL: repositoryURL,
		OCI:           registry.IsOCI(repositoryURL),
	}, nil
}

// Filename returns the name ref's pulled chart archive is stored under,
// both by Pull (as it writes into --output) and Push (as it reads back
// from --input).
func (r Ref) Filename() string {
	return fmt.Sprintf("%s-%s.tgz", r.Name, r.Version)
}
