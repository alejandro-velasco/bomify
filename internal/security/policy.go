package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alejandro-velasco/bomify/internal/prefix"
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
	// Ignore lists vulnerability IDs never to fail a matching package
	// on.
	Ignore []string `json:"ignore,omitempty"`
}

// Gate returns r's FailOn/Ignore as a Gate.
func (r Rule) Gate() (Gate, error) {
	g := Gate{Ignore: r.Ignore}
	if r.FailOn == "" {
		return g, nil
	}
	sev, err := ParseSeverity(r.FailOn)
	if err != nil {
		return Gate{}, fmt.Errorf("scan rule %q: %w", r.Match, err)
	}
	g.FailOn = sev
	return g, nil
}

// Config is the "<baseDir>/conf/scan.json" record: an unordered list of
// Rules, at most one per Match, the most specific match winning (see
// Resolve).
type Config []Rule

// ConfigPath returns the deterministic path of baseDir's scan.json.
func ConfigPath(baseDir string) string {
	return filepath.Join(baseDir, "conf", "scan.json")
}

// ReadConfig reads and parses baseDir's scan.json, returning an empty
// Config if it doesn't exist yet.
func ReadConfig(baseDir string) (Config, error) {
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

// SetRule adds or replaces the rule for rule.Match in baseDir's
// scan.json, after checking its FailOn parses.
func SetRule(baseDir string, rule Rule) error {
	if _, err := rule.Gate(); err != nil {
		return err
	}

	config, err := ReadConfig(baseDir)
	if err != nil {
		return err
	}

	for i := range config {
		if config[i].Match == rule.Match {
			config[i] = rule
			return writeConfig(baseDir, config)
		}
	}

	return writeConfig(baseDir, append(config, rule))
}

// RemoveRule removes the rule for match from baseDir's scan.json,
// returning an error if no such rule exists.
func RemoveRule(baseDir, match string) error {
	config, err := ReadConfig(baseDir)
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
// "/"-separated segments) prefix of ref's repository, reporting ok=false
// if none matches.
func Resolve(rules Config, ref string) (rule Rule, ok bool) {
	repository := prefix.Repository(ref)

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

// writeConfig writes config to baseDir's scan.json.
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
		return fmt.Errorf("marshal scan config: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}
