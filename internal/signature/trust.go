package signature

import (
	"fmt"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/rules"
)

// Rule is one entry in "<baseDir>/conf/trust.json": packages whose
// reference matches Match must carry a signature Verifier's plugin
// verifies before `bomify pull`/`bomify load` restore them.
type Rule struct {
	// Match is a "/"-separated prefix of a package's repository — its
	// reference without any tag or digest, e.g. "registry.example.com",
	// "registry.example.com/team", or "registry.example.com/team/app" —
	// matched at segment boundaries. Empty matches every package.
	Match string `json:"match,omitempty"`
	// Verifier names the signing plugin (bomify-plugin-<Verifier>) that
	// must verify a matching package.
	Verifier string `json:"verifier"`
	// Options are passed through, unparsed, as --option flags to
	// Verifier's "signature verify" — e.g. which key or identity to
	// trust for packages matching this rule.
	Options []string `json:"options,omitempty"`
	// KeyOptions maps a plugin option name to the name of a key in the
	// data directory's managed key store (see AddKey): each is passed as
	// "--option <option>=<path of the stored copy>" (see
	// ResolveKeyOptions). bomify never interprets option names, so which
	// option takes a key file is up to the plugin — e.g. sigstore's
	// "key".
	KeyOptions map[string]string `json:"keyOptions,omitempty"`
	// Provenance requires a matching package to also carry build
	// provenance (see internal/provenance) attested by a signer Verifier's
	// plugin trusts, with these same options.
	Provenance bool `json:"provenance,omitempty"`
}

// Config is the "<baseDir>/conf/trust.json" record: an unordered list of
// Rules, at most one per Match, the most specific match winning (see
// Resolve).
type Config []Rule

func trustFile(baseDir string) rules.File[Rule] {
	return rules.File[Rule]{
		Path: layout.TrustConfig(baseDir),
		Key:  func(r Rule) string { return fmt.Sprintf("match=%q", r.Match) },
	}
}

// Read reads baseDir's trust.json, returning an empty Config if it
// doesn't exist yet.
func Read(baseDir string) (Config, error) {
	return trustFile(baseDir).Read()
}

// SetRule adds or replaces the rule for rule.Match in baseDir's
// trust.json, after checking every key its KeyOptions names is in
// baseDir's managed key store, and that no option is given both as a
// plain option and as a key option.
func SetRule(baseDir string, rule Rule) error {
	for option := range rule.KeyOptions {
		for _, plain := range rule.Options {
			if strings.HasPrefix(plain, option+"=") {
				return fmt.Errorf("option %q given both as --option and as --key-option", option)
			}
		}
	}
	if _, err := keyOptionArgs(baseDir, rule.KeyOptions); err != nil {
		return err
	}
	return trustFile(baseDir).Set(rule)
}

// RemoveRule removes the rule for match from baseDir's trust.json,
// returning an error if no such rule exists.
func RemoveRule(baseDir, match string) error {
	return trustFile(baseDir).Remove(Rule{Match: match})
}

// Resolve picks the rule in rules whose Match is the most specific (most
// "/"-separated segments) prefix of ref's repository (see
// prefix.Repository), reporting ok=false if none matches.
func Resolve(config Config, ref string) (rule Rule, ok bool) {
	return rules.ForReference(config, ref, ruleMatch)
}

func ruleMatch(r Rule) string { return r.Match }

// Policy decides which plugin, if any, must verify a given package
// before it's restored: an explicit Verifier applies to every reference;
// otherwise the best-matching trust.json rule in Rules does (see
// Resolve); otherwise nothing is verified. Skip disables verification
// entirely, even where a rule demands it. The same source decides whether
// build provenance must verify too (see ProvenanceRequired).
type Policy struct {
	// Verifier, if set, is the plugin every reference must verify with,
	// regardless of Rules — bomify pull/load's --verify.
	Verifier Plugin
	// Rules are baseDir's trust.json rules.
	Rules Config
	// Skip disables verification entirely — bomify pull/load's
	// --insecure-skip-verify.
	Skip bool
	// Provenance requires every reference's build provenance to verify —
	// bomify pull/load's --verify-provenance.
	Provenance bool
}

// For reports which plugin must verify ref, and whether one must at all,
// so a caller can tell a package that verified from one nothing asked to
// verify.
//
// Exactly one source decides, checked in this order:
//  1. Skip (--insecure-skip-verify): nothing is verified.
//  2. Verifier (--verify): used as-is for every reference. Rules
//     aren't consulted at all, so a matching rule's plugin and
//     options are ignored rather than combined with the flag's.
//  3. Rules (trust.json): the most specific match, with only its
//     own options.
//  4. Nothing matched: the package is restored unverified.
func (p Policy) For(ref string) (Plugin, bool) {
	if p.Skip {
		return Plugin{}, false
	}
	if p.Verifier.Kind != "" {
		return p.Verifier, true
	}
	if rule, ok := Resolve(p.Rules, ref); ok {
		return Plugin{Kind: rule.Verifier, Options: rule.Options}, true
	}
	return Plugin{}, false
}

// ProvenanceRequired reports whether ref's build provenance must verify,
// with the plugin For picks: always with Provenance (unless Skip);
// otherwise only if the trust rule For uses requires it, so --verify,
// which ignores rules, never inherits one's Provenance.
func (p Policy) ProvenanceRequired(ref string) bool {
	if p.Skip {
		return false
	}
	if p.Provenance {
		return true
	}
	if p.Verifier.Kind != "" {
		return false
	}
	rule, ok := Resolve(p.Rules, ref)
	return ok && rule.Provenance
}
