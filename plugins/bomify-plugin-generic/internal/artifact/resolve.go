// Package artifact resolves component purls to plain HTTP artifact URLs
// and pulls/pushes them with a simple GET/PUT.
package artifact

import (
	"fmt"
	"net/url"
	"path"

	"github.com/package-url/packageurl-go"
)

// Ref identifies a generic artifact and where its purl says to find it.
type Ref struct {
	Name    string
	Version string
	// DownloadURL is where the artifact is fetched from (pull) and, unless
	// overridden by --remote, the base for where it's uploaded to (push).
	DownloadURL string
}

// Resolve parses purlString (pkg:generic/<name>@<version>?download_url=...)
// into a Ref. download_url is the qualifier the package-url spec defines
// for the "generic" purl type.
func Resolve(purlString string) (Ref, error) {
	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return Ref{}, fmt.Errorf("parse purl %q: %w", purlString, err)
	}

	downloadURL := purl.Qualifiers.Map()["download_url"]
	if downloadURL == "" {
		return Ref{}, fmt.Errorf("purl %q has no download_url qualifier", purlString)
	}

	return Ref{Name: purl.Name, Version: purl.Version, DownloadURL: downloadURL}, nil
}

// Filename returns the local filename to save (pull) or read back (push)
// the artifact under: DownloadURL's own filename, when it has one,
// otherwise "<name>-<version>".
func (r Ref) Filename() string {
	if u, err := url.Parse(r.DownloadURL); err == nil {
		if base := path.Base(u.Path); base != "" && base != "." && base != "/" {
			return base
		}
	}

	if r.Version == "" {
		return r.Name
	}
	return fmt.Sprintf("%s-%s", r.Name, r.Version)
}
