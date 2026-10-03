// Package distribution manages bomify's remote-endpoint rules, recorded
// in "<baseDir>/conf/distribution.json" and read by `bomify distribute`
// as a fallback for any component not given a matching --remote on the
// command line.
package distribution

import (
	"fmt"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	"github.com/alejandro-velasco/bomify/internal/rules"
)

// Rule is one entry in "<baseDir>/conf/distribution.json": the remote
// endpoint to use for a component matching both Type and Match. Type and
// Match are each independently optional — empty means "any" — so a Rule
// can be scoped by plugin kind, by origin, by both, or by neither (a
// catch-all). See Resolve for how multiple matching rules are ranked.
type Rule struct {
	// Type is a plugin kind (e.g. "oci", "helm", "generic"). Empty
	// matches a component of any kind.
	Type string `json:"type,omitempty"`
	// Match is a "/"-separated prefix of a component's origin — the Remote
	// its plugin's "remote" subcommand reports (see internal/plugin.Remote
	// and plugins/contracts/component/v1/CONTRACT.md) — e.g. "docker.io",
	// "docker.io/myorg", or "docker.io/myorg/myrepo" — matched at segment
	// boundaries. Empty matches a component of any (or no) origin, but also
	// means there's nothing for Resolve to mirror: see Resolve for how a
	// non-empty Match acts as a prefix substitution rather than a plain
	// lookup key.
	Match string `json:"match,omitempty"`
	// Endpoint is the remote this rule resolves to — see Resolve for how
	// a non-empty Match can extend it with the rest of the component's
	// origin, rather than using it bare.
	Endpoint string `json:"endpoint"`
}

// Config is the "<baseDir>/conf/distribution.json" record: an ordered
// list of Rules, most specific match wins (see Resolve). It's a JSON
// array — not the flat "kind -> endpoint" object bomify used before
// rules existed — so a leftover old-format file fails to parse loudly
// instead of silently reading back as an empty rule set.
type Config []Rule

func distributionFile(baseDir string) rules.File[Rule] {
	return rules.File[Rule]{
		Path: layout.DistributionConfig(baseDir),
		Key:  func(r Rule) string { return fmt.Sprintf("type=%q match=%q", r.Type, r.Match) },
	}
}

// Read reads baseDir's distribution.json, returning an empty Config if
// it doesn't exist yet.
func Read(baseDir string) (Config, error) {
	return distributionFile(baseDir).Read()
}

// SetRule adds or updates the rule for (ruleType, match) in
// "<baseDir>/conf/distribution.json", merging into whatever is already
// there. Calling it again for the same (ruleType, match) pair overwrites
// its endpoint; otherwise a new rule is appended.
func SetRule(baseDir, ruleType, match, endpoint string) error {
	return distributionFile(baseDir).Set(Rule{Type: ruleType, Match: match, Endpoint: endpoint})
}

// RemoveRule removes the rule for (ruleType, match) from
// "<baseDir>/conf/distribution.json", returning an error if no such rule
// exists.
func RemoveRule(baseDir, ruleType, match string) error {
	return distributionFile(baseDir).Remove(Rule{Type: ruleType, Match: match})
}

// Resolve picks the best rule in rules for a component of the given kind (see
// plugin.Detect) whose origin is origin — its plugin's own report of where it
// comes from or is published under (see internal/plugin.Remote and
// plugins/contracts/component/v1/CONTRACT.md's "remote" subcommand), in
// whatever shape that plugin's kind uses; any URL scheme (e.g. "https://",
// "oci://") and surrounding slashes are stripped before matching, so origin
// lines up with a Match regardless of how the plugin formatted it. Candidates
// are ranked first by how specific their Match is — more "/"-separated
// segments wins, since that names a narrower, more concrete target — and,
// among equally specific matches, a Rule whose Type also matches kind wins
// over one with no Type at all. It reports ok=false if no rule matches at
// all.
//
// The winning rule's Endpoint isn't necessarily returned verbatim: when
// its Match is non-empty, Resolve acts as a mirror — origin's portion
// past the matched prefix is preserved and appended to Endpoint, so a
// rule matching "docker.io/myorg" against "docker.io/myorg/sub/repo"
// resolves to "<endpoint>/sub/repo", not just "<endpoint>". A rule with
// no Match (a type-only or catch-all rule) has no prefix to subtract, so
// its Endpoint is returned bare — the plugin's own push logic decides
// what to publish under it, exactly as if --remote had named it directly.
func Resolve(config Config, kind, origin string) (destination string, ok bool) {
	origin = prefix.Normalize(origin)

	// A rule wins if it's more specific (more Match segments), or it ties
	// on specificity but narrows by Type where the other doesn't.
	best, ok := rules.Best(config, func(r Rule) (int, bool) {
		if r.Type != "" && r.Type != kind {
			return 0, false
		}
		segments, ok := rules.PrefixScore(origin, r.Match)
		score := 2 * segments
		if r.Type != "" {
			score++
		}
		return score, ok
	})
	if !ok {
		return "", false
	}
	return mirror(best, origin), true
}

// mirror returns what rule resolves to for origin: its bare Endpoint if
// Match is empty (nothing to preserve), otherwise Endpoint with origin's
// remainder past the matched prefix appended — see Resolve.
func mirror(rule Rule, origin string) string {
	match := prefix.Normalize(rule.Match)
	if match == "" {
		return rule.Endpoint
	}

	// prefix.Matches already established match is a segment-boundary
	// prefix of origin, so this TrimPrefix pair is exact: either origin
	// == match (remainder == "") or the next character was "/".
	remainder := strings.TrimPrefix(strings.TrimPrefix(origin, match), "/")
	if remainder == "" {
		return rule.Endpoint
	}

	return strings.TrimSuffix(rule.Endpoint, "/") + "/" + remainder
}
