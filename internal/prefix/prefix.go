// Package prefix implements the "/"-separated, segment-boundary prefix
// matching that bomify's rule files share: conf/distribution.json's
// Match against a component's origin (see internal/distribution), and
// conf/trust.json's Match against a package reference (see
// internal/signature).
package prefix

import "strings"

// Matches reports whether match — a "/"-separated prefix, e.g.
// "docker.io/myorg" — matches address at segment boundaries:
// "docker.io/org" matches "docker.io/org/repo" but not
// "docker.io/organization". Both are normalized first (see Normalize). An
// empty match matches any address, including an empty one.
func Matches(address, match string) bool {
	match = Normalize(match)
	if match == "" {
		return true
	}
	address = Normalize(address)
	if address == "" {
		return false
	}

	addressParts := strings.Split(address, "/")
	matchParts := strings.Split(match, "/")
	if len(matchParts) > len(addressParts) {
		return false
	}
	for i, part := range matchParts {
		if addressParts[i] != part {
			return false
		}
	}
	return true
}

// Segments returns how many "/"-separated segments match has, for ranking
// rules by specificity. An empty match — matching any address — is the
// least specific, at 0.
func Segments(match string) int {
	match = Normalize(match)
	if match == "" {
		return 0
	}
	return len(strings.Split(match, "/"))
}

// Normalize strips address's URL scheme (e.g. "oci://"), if any, and any
// leading/trailing "/", so values written by hand (with a scheme or a
// trailing slash) still compare equal to machine-produced ones.
func Normalize(address string) string {
	if i := strings.Index(address, "://"); i >= 0 {
		address = address[i+len("://"):]
	}
	return strings.Trim(address, "/")
}
