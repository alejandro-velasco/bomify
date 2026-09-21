// Package distribution manages bomify's remote-endpoint rules, recorded
// in "<baseDir>/conf/distribution.json" and read by `bomify distribute`
// as a fallback for any component not given a matching --remote on the
// command line.
package distribution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// Match is a "/"-separated prefix of a component's origin — the
	// Remote its plugin's "remote" subcommand reports (see
	// internal/plugin.Remote and plugins/CONTRACT.md) — e.g. "docker.io",
	// "docker.io/myorg", or "docker.io/myorg/myrepo" — matched at segment
	// boundaries. Empty matches a component of any (or no) origin, but
	// also means there's nothing for Resolve to mirror: see Resolve for
	// how a non-empty Match acts as a prefix substitution rather than a
	// plain lookup key.
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

// ConfigPath returns the deterministic path of baseDir's distribution.json.
func ConfigPath(baseDir string) string {
	return filepath.Join(baseDir, "conf", "distribution.json")
}

// Read reads and parses baseDir's distribution.json, returning an empty
// Config if it doesn't exist yet.
func Read(baseDir string) (Config, error) {
	path := ConfigPath(baseDir)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return config, nil
}

// SetRule adds or updates the rule for (ruleType, match) in
// "<baseDir>/conf/distribution.json", merging into whatever is already
// there. Calling it again for the same (ruleType, match) pair overwrites
// its endpoint; otherwise a new rule is appended.
func SetRule(baseDir, ruleType, match, endpoint string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}

	for i, rule := range config {
		if rule.Type == ruleType && rule.Match == match {
			config[i].Endpoint = endpoint
			return writeConfig(baseDir, config)
		}
	}

	config = append(config, Rule{Type: ruleType, Match: match, Endpoint: endpoint})

	return writeConfig(baseDir, config)
}

// RemoveRule removes the rule for (ruleType, match) from
// "<baseDir>/conf/distribution.json", returning an error if no such rule
// exists.
func RemoveRule(baseDir, ruleType, match string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}

	for i, rule := range config {
		if rule.Type == ruleType && rule.Match == match {
			config = append(config[:i], config[i+1:]...)
			return writeConfig(baseDir, config)
		}
	}

	return fmt.Errorf("no such rule: type=%q match=%q", ruleType, match)
}

// Resolve picks the best rule in rules for a component of the given kind
// (see plugin.Detect) whose origin is origin — its plugin's own report of
// where it comes from or is published under (see internal/plugin.Remote
// and plugins/CONTRACT.md's "remote" subcommand), in whatever shape that
// plugin's kind uses; any URL scheme (e.g. "https://", "oci://") and
// surrounding slashes are stripped before matching, so origin lines up
// with a Match regardless of how the plugin formatted it. Candidates are
// ranked first by how specific their Match is — more "/"-separated
// segments wins, since that names a narrower, more concrete target — and,
// among equally specific matches, a Rule whose Type also matches kind
// wins over one with no Type at all. It reports ok=false if no rule
// matches at all.
//
// The winning rule's Endpoint isn't necessarily returned verbatim: when
// its Match is non-empty, Resolve acts as a mirror — origin's portion
// past the matched prefix is preserved and appended to Endpoint, so a
// rule matching "docker.io/myorg" against "docker.io/myorg/sub/repo"
// resolves to "<endpoint>/sub/repo", not just "<endpoint>". A rule with
// no Match (a type-only or catch-all rule) has no prefix to subtract, so
// its Endpoint is returned bare — the plugin's own push logic decides
// what to publish under it, exactly as if --remote had named it directly.
func Resolve(rules Config, kind, origin string) (destination string, ok bool) {
	origin = normalizeAddress(origin)

	var best *Rule
	bestSegments := -1
	bestTyped := false

	for i, rule := range rules {
		if rule.Type != "" && rule.Type != kind {
			continue
		}
		if !matchesOrigin(origin, rule.Match) {
			continue
		}

		segments := matchSegments(rule.Match)
		typed := rule.Type != ""

		// A rule wins if it's more specific (more Match segments), or it
		// ties on specificity but narrows by Type where the current best
		// doesn't.
		moreSpecific := segments > bestSegments
		tiebreakOnType := segments == bestSegments && typed && !bestTyped
		if best == nil || moreSpecific || tiebreakOnType {
			best = &rules[i]
			bestSegments = segments
			bestTyped = typed
		}
	}

	if best == nil {
		return "", false
	}
	return mirror(*best, origin), true
}

// mirror returns what rule resolves to for origin: its bare Endpoint if
// Match is empty (nothing to preserve), otherwise Endpoint with origin's
// remainder past the matched prefix appended — see Resolve.
func mirror(rule Rule, origin string) string {
	match := normalizeAddress(rule.Match)
	if match == "" {
		return rule.Endpoint
	}

	// matchesOrigin already established match is a segment-boundary
	// prefix of origin, so this TrimPrefix pair is exact: either origin
	// == match (remainder == "") or the next character was "/".
	remainder := strings.TrimPrefix(strings.TrimPrefix(origin, match), "/")
	if remainder == "" {
		return rule.Endpoint
	}

	return strings.TrimSuffix(rule.Endpoint, "/") + "/" + remainder
}

// matchesOrigin reports whether match — a "/"-separated prefix, e.g.
// "docker.io/myorg" — matches origin at segment boundaries: "docker.io/org"
// matches "docker.io/org/repo" but not "docker.io/organization". An empty
// match matches any origin, including an empty one (a component whose
// purl declared no repository_url/download_url at all).
func matchesOrigin(origin, match string) bool {
	match = normalizeAddress(match)
	if match == "" {
		return true
	}
	if origin == "" {
		return false
	}

	originParts := strings.Split(origin, "/")
	matchParts := strings.Split(match, "/")
	if len(matchParts) > len(originParts) {
		return false
	}
	for i, part := range matchParts {
		if originParts[i] != part {
			return false
		}
	}
	return true
}

// matchSegments returns how many "/"-separated segments match has, for
// ranking rules by specificity in Resolve. An empty match — matching any
// origin — is the least specific, at 0.
func matchSegments(match string) int {
	match = normalizeAddress(match)
	if match == "" {
		return 0
	}
	return len(strings.Split(match, "/"))
}

// normalizeAddress strips address's URL scheme (e.g. "oci://"), if any,
// and any leading/trailing "/", so values written by hand (with a scheme
// or a trailing slash) still compare equal to Origin's own output.
func normalizeAddress(address string) string {
	if i := strings.Index(address, "://"); i >= 0 {
		address = address[i+len("://"):]
	}
	return strings.Trim(address, "/")
}

// writeConfig writes config to baseDir's distribution.json.
func writeConfig(baseDir string, config Config) error {
	path := ConfigPath(baseDir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create conf directory: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config); err != nil {
		return fmt.Errorf("marshal distribution config: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}
