package signature

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/rules"
)

// Rule is one entry in "<baseDir>/conf/trust.json": packages whose
// reference matches Match must carry signatures that Require of Signers
// verify before `bomify pull`/`bomify load` restore them.
type Rule struct {
	// Match is a "/"-separated prefix of a package's repository — its
	// reference without any tag or digest, e.g. "registry.example.com",
	// "registry.example.com/team", or "registry.example.com/team/app" —
	// matched at segment boundaries. Empty matches every package.
	Match string `json:"match,omitempty"`
	// Signers are the signatures a matching package may need, each
	// verified on its own.
	Signers []Signer `json:"signers"`
	// Require is how many of Signers must each verify one of the
	// package's signatures; 0 means all of them.
	Require int `json:"require,omitempty"`
	// Provenance requires a matching package to also carry build
	// provenance (see internal/provenance) attested by a signer one of
	// Signers trusts, with that signer's options.
	Provenance bool `json:"provenance,omitempty"`
}

// Signer is one signature a trust rule asks for: one that the plugin
// Kind names verifies with Options and KeyOptions.
type Signer struct {
	// Name tells a rule's signers apart, in errors and listings. A rule
	// may have one unnamed signer, as "bomify trust create" makes without
	// --signer.
	Name string `json:"name,omitempty"`
	// Kind names the signing plugin (bomify-plugin-<Kind>) that
	// verifies this signer's signature.
	Kind string `json:"plugin"`
	// Options are passed through, unparsed, as --option flags to
	// Kind's "signature verify" — e.g. which key or identity to
	// trust.
	Options []string `json:"options,omitempty"`
	// KeyOptions maps a plugin option name to the name of a key in the
	// data directory's managed key store (see AddKey): each is passed as
	// "--option <option>=<path of the stored copy>" (see
	// ResolveKeyOptions). bomify never interprets option names, so which
	// option takes a key file is up to the plugin — e.g. sigstore's
	// "key".
	KeyOptions map[string]string `json:"keyOptions,omitempty"`
}

// plugin returns the plugin and options that verify s.
func (s Signer) plugin() Plugin {
	return Plugin{Kind: s.Kind, Options: s.Options}
}

// SignerError is an error about one of a trust rule's signers, naming it.
type SignerError struct {
	// Name is the signer's, "" for the rule's unnamed signer.
	Name string
	Err  error
}

func (e *SignerError) Error() string {
	if e.Name == "" {
		return "the unnamed signer: " + e.Err.Error()
	}
	return fmt.Sprintf("signer %q: %v", e.Name, e.Err)
}

func (e *SignerError) Unwrap() error { return e.Err }

// Required is how many of r's signers must verify.
func (r Rule) Required() int {
	if r.Require == 0 {
		return len(r.Signers)
	}
	return r.Require
}

// SetSigner adds signer to r, replacing the signer of the same name if r
// has one.
func (r *Rule) SetSigner(signer Signer) {
	sameName := func(existing Signer) bool { return existing.Name == signer.Name }
	if index := slices.IndexFunc(r.Signers, sameName); index >= 0 {
		r.Signers[index] = signer
		return
	}
	r.Signers = append(r.Signers, signer)
}

// validate checks r makes sense on its own: at least one signer, each
// named uniquely (at most one unnamed) and naming a plugin, no option
// given both plainly and as a key option, and a Require r's signers can
// meet.
func (r Rule) validate() error {
	if len(r.Signers) == 0 {
		return errors.New("no signers")
	}
	seen := map[string]bool{}
	for _, signer := range r.Signers {
		if seen[signer.Name] {
			return &SignerError{
				Name: signer.Name,
				Err:  errors.New("given more than once"),
			}
		}
		if signer.Kind == "" {
			return &SignerError{
				Name: signer.Name,
				Err:  errors.New("no plugin"),
			}
		}
		seen[signer.Name] = true
		for option := range signer.KeyOptions {
			for _, plain := range signer.Options {
				if strings.HasPrefix(plain, option+"=") {
					return &SignerError{
						Name: signer.Name,
						Err:  fmt.Errorf("option %q given both as --option and as --key-option", option),
					}
				}
			}
		}
	}
	if r.Require < 0 || r.Require > len(r.Signers) {
		return fmt.Errorf("requires %d signers but has %d", r.Require, len(r.Signers))
	}
	return nil
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
// trust.json, after validating it and checking every key its signers'
// KeyOptions name is in baseDir's managed key store.
func SetRule(baseDir string, rule Rule) error {
	if err := rule.validate(); err != nil {
		return fmt.Errorf("trust rule %q: %w", rules.Display(rule.Match), err)
	}
	for _, signer := range rule.Signers {
		if _, err := keyOptionArgs(baseDir, signer.KeyOptions); err != nil {
			return &SignerError{
				Name: signer.Name,
				Err:  err,
			}
		}
	}
	return trustFile(baseDir).Set(rule)
}

// UpdateRule applies update to baseDir's rule for match, or to a new,
// empty rule for match if there's none, and stores the result as
// SetRule does.
func UpdateRule(baseDir, match string, update func(*Rule)) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}
	rule := Rule{Match: match}
	if i := slices.IndexFunc(config, func(r Rule) bool { return r.Match == match }); i >= 0 {
		rule = config[i]
	}
	update(&rule)
	return SetRule(baseDir, rule)
}

// RemoveRule removes the rule for match from baseDir's trust.json,
// returning an error if no such rule exists.
func RemoveRule(baseDir, match string) error {
	return trustFile(baseDir).Remove(Rule{Match: match})
}

// RemoveSigner removes the signer called name from baseDir's rule for
// match, and the rule itself if that was its last signer. It fails if
// there's no such signer, or if the rule would then require more signers
// than it has.
func RemoveSigner(baseDir, match, name string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(config, func(r Rule) bool { return r.Match == match })
	if i < 0 {
		return fmt.Errorf("no such rule: match=%q", match)
	}
	rule := config[i]
	before := len(rule.Signers)
	rule.Signers = slices.DeleteFunc(slices.Clone(rule.Signers), func(signer Signer) bool { return signer.Name == name })
	switch {
	case len(rule.Signers) == before:
		return &SignerError{
			Name: name,
			Err:  fmt.Errorf("not in trust rule %q", rules.Display(match)),
		}
	case len(rule.Signers) == 0:
		return RemoveRule(baseDir, match)
	}
	return SetRule(baseDir, rule)
}

// Resolve picks the rule in rules whose Match is the most specific (most
// "/"-separated segments) prefix of ref's repository (see
// prefix.Repository), reporting ok=false if none matches.
func Resolve(config Config, ref string) (rule Rule, ok bool) {
	return rules.ForReference(config, ref, ruleMatch)
}

func ruleMatch(r Rule) string { return r.Match }

// Requirement is the signatures a package must carry: Require of Signers
// (all of them if Require is 0) must each verify one of its signatures.
type Requirement struct {
	Signers []Signer
	Require int
}

// required is how many of r's signers must verify.
func (r Requirement) required() int {
	return Rule{Signers: r.Signers, Require: r.Require}.Required()
}

// Policy decides which signatures, if any, a given package must carry
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

// For reports which signatures ref must carry, and whether it must carry
// any at all, so a caller can tell a package that verified from one
// nothing asked to verify.
//
// Exactly one source decides, checked in this order:
//  1. Skip (--insecure-skip-verify): nothing is verified.
//  2. Verifier (--verify): one signature it verifies, for every
//     reference. Rules aren't consulted at all, so a matching rule's
//     signers are ignored rather than combined with the flag's.
//  3. Rules (trust.json): the most specific match's signers and
//     Require.
//  4. Nothing matched: the package is restored unverified.
func (p Policy) For(ref string) (Requirement, bool) {
	if p.Skip {
		return Requirement{}, false
	}
	if p.Verifier.Kind != "" {
		return Requirement{Signers: []Signer{{Kind: p.Verifier.Kind, Options: p.Verifier.Options}}}, true
	}
	if rule, ok := Resolve(p.Rules, ref); ok {
		return Requirement{Signers: rule.Signers, Require: rule.Require}, true
	}
	return Requirement{}, false
}

// ProvenanceRequired reports whether ref's build provenance must verify,
// with a signer For picks: always with Provenance (unless Skip);
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
