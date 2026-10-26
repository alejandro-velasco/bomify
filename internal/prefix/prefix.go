// Package prefix implements the "/"-separated, segment-boundary prefix
// matching that bomify's rule files share: conf/trust.json's and
// conf/scan.json's Match against a package reference (see
// internal/signature and internal/security).
package prefix

import "strings"

// Matches reports whether match — a "/"-separated prefix, e.g.
// "docker.io/myorg" — matches address at segment boundaries:
// "docker.io/org" matches "docker.io/org/repo" but not
// "docker.io/organization". Both are normalized first (see normalize). An
// empty match matches any address, including an empty one.
func Matches(address, match string) bool {
	match = normalize(match)
	if match == "" {
		return true
	}
	address = normalize(address)
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
	match = normalize(match)
	if match == "" {
		return 0
	}
	return len(strings.Split(match, "/"))
}

// normalize strips address's URL scheme (e.g. "oci://"), if any, and any
// leading/trailing "/", lowercases it, and canonicalizes its registry
// host (see canonicalHost), so every spelling of one repository compares
// equal: a rule can't be sidestepped by writing its registry another way.
func normalize(address string) string {
	if i := strings.Index(address, "://"); i >= 0 {
		address = address[i+len("://"):]
	}
	address = strings.ToLower(strings.Trim(address, "/"))
	host, rest, hasRest := strings.Cut(address, "/")
	if !isHost(host) {
		return address
	}
	host = canonicalHost(host)
	if !hasRest {
		return host
	}
	return host + "/" + rest
}

// dockerHubAliases are the other names Docker Hub's registry answers to.
var dockerHubAliases = map[string]bool{
	"index.docker.io":      true,
	"registry-1.docker.io": true,
}

// isHost reports whether segment, an address's first, names a registry
// host rather than a repository, as Docker decides: it has a "." or a
// port, or is "localhost".
func isHost(segment string) bool {
	return strings.ContainsAny(segment, ".:") || segment == "localhost"
}

// canonicalHost drops host's trailing "." (a fully qualified DNS name) and
// its port if it's HTTPS's default, 443, and names Docker Hub as
// docker.io, whichever alias was used.
func canonicalHost(host string) string {
	name, port, hasPort := strings.Cut(host, ":")
	name = strings.TrimSuffix(name, ".")
	if dockerHubAliases[name] {
		name = "docker.io"
	}
	if hasPort && port != "443" {
		return name + ":" + port
	}
	return name
}

// Repository strips ref's digest ("@sha256:...") and tag (":v1", only
// when it follows the last "/", so a registry port isn't mistaken for
// one), leaving just the repository a package rule matches against. It
// deliberately doesn't require ref to be fully qualified, since `bomify
// save`/`bomify load` tags needn't name a registry at all.
func Repository(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}
