package push

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
	orasregistry "oras.land/oras-go/v2/registry"
)

// The purl qualifiers naming uses: an image's tag, and the platform that
// components sharing a site as one index differ in.
const (
	qualifierTag  = "tag"
	qualifierOS   = "os"
	qualifierArch = "arch"
)

// componentSite is where Push tags a component beside its package:
// <package repository>/<path>:<tag> (see componentSiteOf), and the
// platform it's for, if its purl names one.
type componentSite struct {
	// path is the repository's, relative to the package's.
	path string
	// tag is what the component is tagged, or "" for an image pinned by
	// digest, which is published by digest, untagged.
	tag string
	// pinned is the digest the purl pins an image to, which tells sites
	// of untagged images apart.
	pinned string
	// os and arch are the purl's "os" and "arch" qualifiers: components
	// that differ only in them share a site, as one index.
	os, arch string
	// unqualified is the purl without "os" and "arch", which components
	// sharing a site as platforms of one index must agree on.
	unqualified string
}

// reference returns s relative to the package's repository, as
// "<path>:<tag>", or for an image pinned by digest, "<path>@<digest>".
func (s componentSite) reference() string {
	if s.tag == "" {
		return s.path + "@" + s.pinned
	}
	return s.path + ":" + s.tag
}

// hasPlatform reports whether s is for a platform, as its purl's "os" or
// "arch" qualifier says.
func (s componentSite) hasPlatform() bool {
	return s.os != "" || s.arch != ""
}

// isOtherPlatformOf reports whether s and other are distinct platforms of
// one component: the same purl but for its "os" and "arch" qualifiers,
// which both have and which differ.
func (s componentSite) isOtherPlatformOf(other componentSite) bool {
	if !s.hasPlatform() || !other.hasPlatform() {
		return false
	}
	if s.unqualified != other.unqualified {
		return false
	}
	return s.os != other.os || s.arch != other.arch
}

// componentSiteOf returns where the component purl names is tagged beside
// its package: one repository segment for each of its type, namespace
// segments, and name, each lowercased and made valid (see
// repositorySegment), tagged with its version (see versionTag), or an
// image with its "tag" qualifier, if it has one. An image pinned to a
// digest without one is published by digest. Other qualifiers than "os"
// and "arch" are left out, as is a subpath.
func componentSiteOf(purl packageurl.PackageURL) (componentSite, error) {
	// The type, each of the namespace's segments (a namespace may hold
	// several, as golang's do), and the name.
	segments := []string{purl.Type}
	if purl.Namespace != "" {
		segments = append(segments, strings.Split(purl.Namespace, "/")...)
	}
	segments = append(segments, purl.Name)
	valid := make([]string, 0, len(segments))
	for _, segment := range segments {
		validSegment := repositorySegment(segment)
		if validSegment == "" {
			return componentSite{}, fmt.Errorf("%s: %q can't be a repository name", purl.ToString(), segment)
		}
		valid = append(valid, validSegment)
	}

	qualifiers := purl.Qualifiers.Map()
	// An image's tag is its "tag" qualifier, else its version, unless
	// that's the digest it's pinned to.
	tagged := purl.Version
	var pinned string
	if purl.Type == packageurl.TypeOCI || purl.Type == packageurl.TypeDocker {
		if strings.HasPrefix(purl.Version, "sha256:") {
			pinned, tagged = purl.Version, ""
		}
		if qualifiers[qualifierTag] != "" {
			tagged = qualifiers[qualifierTag]
		}
	}
	var tag string
	if tagged != "" || pinned == "" {
		var err error
		if tag, err = versionTag(tagged); err != nil {
			return componentSite{}, fmt.Errorf("%s: %w", purl.ToString(), err)
		}
	}

	unqualified := purl
	unqualified.Qualifiers = nil
	for _, qualifier := range purl.Qualifiers {
		if qualifier.Key != qualifierOS && qualifier.Key != qualifierArch {
			unqualified.Qualifiers = append(unqualified.Qualifiers, qualifier)
		}
	}

	site := componentSite{
		path:        strings.Join(valid, "/"),
		tag:         tag,
		pinned:      pinned,
		os:          qualifiers[qualifierOS],
		arch:        qualifiers[qualifierArch],
		unqualified: unqualified.ToString(),
	}
	return site, nil
}

// repositorySegment makes segment one path component of an OCI
// repository name, [a-z0-9]+ joined by ".", "_", "__", or runs of "-":
// lowercased, every other character taken as a separator, a run of
// separators that isn't one of those as "-", and none at either end. It
// returns "" for a segment with no letter or digit.
func repositorySegment(segment string) string {
	var out, separators strings.Builder
	for _, r := range strings.ToLower(segment) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if separators.Len() > 0 && out.Len() > 0 {
				out.WriteString(validSeparator(separators.String()))
			}
			separators.Reset()
			out.WriteRune(r)
			continue
		}
		separators.WriteRune(r)
	}
	return out.String()
}

// validSeparator returns run, a run of characters between letters and
// digits, if it's a separator an OCI repository name allows, and "-"
// otherwise.
func validSeparator(run string) string {
	if run == "." || run == "_" || run == "__" || strings.Trim(run, "-") == "" {
		return run
	}
	return "-"
}

// versionTag returns version as an OCI tag: "latest" for none, and "+",
// which a tag can't hold, as "_", as Helm does. Any other version that
// isn't a valid tag (see orasregistry.Reference.ValidateReferenceAsTag) is
// an error.
func versionTag(version string) (string, error) {
	if version == "" {
		return "latest", nil
	}
	tag := strings.ReplaceAll(version, "+", "_")
	reference := orasregistry.Reference{Reference: tag}
	if err := reference.ValidateReferenceAsTag(); err != nil {
		return "", fmt.Errorf("version %q can't be a tag", version)
	}
	return tag, nil
}
