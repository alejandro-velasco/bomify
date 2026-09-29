package signature

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/prefix"
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
}

// Config is the "<baseDir>/conf/trust.json" record: an unordered list of
// Rules, at most one per Match, the most specific match winning (see
// Resolve).
type Config []Rule

// ConfigPath returns the deterministic path of baseDir's trust.json.
func ConfigPath(baseDir string) string {
	return filepath.Join(baseDir, "conf", "trust.json")
}

// Read reads and parses baseDir's trust.json, returning an empty Config
// if it doesn't exist yet.
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

// SetRule adds or replaces the rule for match in baseDir's trust.json.
func SetRule(baseDir, match, verifier string, options []string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}

	rule := Rule{Match: match, Verifier: verifier, Options: options}
	for i := range config {
		if config[i].Match == match {
			config[i] = rule
			return writeConfig(baseDir, config)
		}
	}

	return writeConfig(baseDir, append(config, rule))
}

// RemoveRule removes the rule for match from baseDir's trust.json,
// returning an error if no such rule exists.
func RemoveRule(baseDir, match string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}

	for i, rule := range config {
		if rule.Match == match {
			config = append(config[:i], config[i+1:]...)
			return writeConfig(baseDir, config)
		}
	}

	return fmt.Errorf("no such rule: match=%q", match)
}

// Resolve picks the rule in rules whose Match is the most specific (most
// "/"-separated segments) prefix of ref's repository (see Repository),
// reporting ok=false if none matches.
func Resolve(rules Config, ref string) (rule Rule, ok bool) {
	repository := Repository(ref)

	best := -1
	for _, candidate := range rules {
		if !prefix.Matches(repository, candidate.Match) {
			continue
		}
		if segments := prefix.Segments(candidate.Match); segments > best {
			rule, best, ok = candidate, segments, true
		}
	}
	return rule, ok
}

// Repository strips ref's digest ("@sha256:...") and tag (":v1", only
// when it follows the last "/", so a registry port isn't mistaken for
// one), leaving just the repository a trust rule matches against. It
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

// Policy decides which plugin, if any, must verify a given package
// before it's restored: an explicit Verifier applies to every reference;
// otherwise the best-matching trust.json rule in Rules does (see
// Resolve); otherwise nothing is verified. Skip disables verification
// entirely, even where a rule demands it.
type Policy struct {
	// Verifier, if set, is the plugin every reference must verify with,
	// regardless of Rules — bomify pull/load's --verify.
	Verifier Plugin
	// Rules are baseDir's trust.json rules.
	Rules Config
	// Skip disables verification entirely — bomify pull/load's
	// --insecure-skip-verify.
	Skip bool
}

// For reports which plugin must verify ref, and whether one must at
// all. It logs a warning when Skip overrides a rule that matched, since
// that's a policy being deliberately bypassed rather than simply absent.
//
// Exactly one source decides, checked in this order:
//  1. Skip (--insecure-skip-verify): nothing is verified.
//  2. Verifier (--verify): used as-is for every reference. Rules
//     aren't consulted at all, so a matching rule's plugin and
//     options are ignored rather than combined with the flag's.
//  3. Rules (trust.json): the most specific match, with only its
//     own options.
//  4. Nothing matched: the package is restored unverified.
func (p Policy) For(ref string, logger *slog.Logger) (Plugin, bool) {
	if p.Skip {
		if rule, ok := Resolve(p.Rules, ref); ok {
			logger.Warn("skipping signature verification required by trust rule", "reference", ref, "match", rule.Match, "verifier", rule.Verifier)
		}
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

// writeConfig writes config to baseDir's trust.json.
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
		return fmt.Errorf("marshal trust config: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}
