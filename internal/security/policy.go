package security

import (
	"fmt"
	"slices"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/rules"
)

// Rule is one entry in "<baseDir>/conf/scan.json": the scanning policy
// for packages whose reference matches Match.
type Rule struct {
	// Match is a "/"-separated prefix of a package's repository — its
	// reference without any tag or digest (see prefix.Repository) —
	// matched at segment boundaries. Empty matches every package.
	Match string `json:"match,omitempty"`
	// Scanner names the scanning plugin (bomify-plugin-<Scanner>) that
	// scans a matching package.
	Scanner string `json:"scanner"`
	// FailOn is the severity (see ParseSeverity) at or above which a
	// matching package fails its scan. Empty never fails it.
	FailOn string `json:"failOn,omitempty"`
	// VEX names documents in the data directory's managed VEX store (see
	// AddVEX and ResolveVEX) whose statements exempt a matching package's
	// vulnerabilities from FailOn — names, not paths, so a rule keeps
	// meaning the same thing wherever the files it was built from end up.
	// There's deliberately no list of bare vulnerability IDs to ignore: a
	// standing exemption should say which component it applies to and why,
	// which is what VEX records.
	VEX []string `json:"vex,omitempty"`
	// On lists the lifecycle hooks (see Hooks) at which a matching
	// package is scanned with Scanner and gated on FailOn automatically.
	// Only "pull" (which covers load too) exists: it's the one place a
	// hook does what running "bomify security scan" separately can't —
	// refuse a package before anything of it is written. Empty means
	// none; the rule then only applies to "bomify security scan".
	On []string `json:"on,omitempty"`
}

// The lifecycle hooks a Rule can name in On.
const HookPull = "pull"

// Hooks lists every hook a Rule can name in On.
var Hooks = []string{HookPull}

// AppliesOn reports whether r scans packages automatically at hook.
func (r Rule) AppliesOn(hook string) bool {
	return slices.Contains(r.On, hook)
}

// Gate returns r's FailOn as a Gate, with no VEX loaded (see
// Rule.VEX).
func (r Rule) Gate() (Gate, error) {
	if r.FailOn == "" {
		return Gate{}, nil
	}
	sev, err := ParseSeverity(r.FailOn)
	if err != nil {
		return Gate{}, fmt.Errorf("scan rule %q: %w", r.Match, err)
	}
	return Gate{FailOn: sev}, nil
}

// Config is the "<baseDir>/conf/scan.json" record: an unordered list of
// Rules, at most one per Match, the most specific match winning (see
// Resolve).
type Config []Rule

func scanFile(baseDir string) rules.File[Rule] {
	return rules.File[Rule]{
		Path: layout.ScanConfig(baseDir),
		Key:  func(r Rule) string { return fmt.Sprintf("match=%q", r.Match) },
	}
}

// Read reads baseDir's scan.json, returning an empty Config if it
// doesn't exist yet.
func Read(baseDir string) (Config, error) {
	return scanFile(baseDir).Read()
}

// SetRule adds or replaces the rule for rule.Match in baseDir's
// scan.json, after checking its FailOn parses and every VEX document it
// names is in baseDir's managed VEX store.
func SetRule(baseDir string, rule Rule) error {
	if _, err := rule.Gate(); err != nil {
		return err
	}
	for _, hook := range rule.On {
		if !slices.Contains(Hooks, hook) {
			return fmt.Errorf("unknown hook %q (want any of %s)", hook, strings.Join(Hooks, ", "))
		}
	}
	// A scan at a hook is only ever a gate: one with nothing to refuse on
	// would scan every pull for nothing.
	if len(rule.On) > 0 && rule.FailOn == "" {
		return fmt.Errorf("--on %s needs --fail-on: a scan on pull only refuses packages; to just scan, run \"bomify security scan\" after pulling", strings.Join(rule.On, ","))
	}
	if _, err := ResolveVEX(baseDir, rule.VEX); err != nil {
		return err
	}
	return scanFile(baseDir).Set(rule)
}

// RemoveRule removes the rule for match from baseDir's scan.json,
// returning an error if no such rule exists.
func RemoveRule(baseDir, match string) error {
	return scanFile(baseDir).Remove(Rule{Match: match})
}

// Resolve picks the rule in rules whose Match is the most specific (most
// "/"-separated segments) prefix of ref's repository (see
// prefix.Repository), reporting ok=false if none matches.
func Resolve(config Config, ref string) (rule Rule, ok bool) {
	return rules.ForReference(config, ref, ruleMatch)
}

func ruleMatch(r Rule) string { return r.Match }
