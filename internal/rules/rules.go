// Package rules implements what bomify's JSON rule files under
// "<data-dir>/conf" — distribution.json (internal/distribution),
// trust.json (internal/signature), and scan.json (internal/security) —
// have in common: storage as an unordered JSON array with at most one rule
// per identity, and resolution by most specific "/"-segment prefix match
// (see internal/prefix). What a rule means, and what makes one valid, is
// left to each rule file's own package.
package rules

import (
	"fmt"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/prefix"
)

// File is one rule file: a JSON array of R, at most one rule per Key.
type File[R any] struct {
	// Path is the file's location (see internal/layout).
	Path string
	// Key identifies a rule — two rules with the same Key are the same
	// rule — and describes it in errors, e.g. `match="docker.io"`.
	Key func(R) string
}

// Read returns every rule in f, or none if it doesn't exist yet.
func (f File[R]) Read() ([]R, error) {
	rules := []R{}
	if err := fsutil.ReadJSON(f.Path, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// Set adds rule to f, replacing any rule with the same Key in place.
func (f File[R]) Set(rule R) error {
	rules, err := f.Read()
	if err != nil {
		return err
	}

	key := f.Key(rule)
	for i := range rules {
		if f.Key(rules[i]) == key {
			rules[i] = rule
			return fsutil.WriteJSON(f.Path, rules)
		}
	}
	return fsutil.WriteJSON(f.Path, append(rules, rule))
}

// Remove removes the rule whose Key is key's, failing if there's none.
func (f File[R]) Remove(key R) error {
	rules, err := f.Read()
	if err != nil {
		return err
	}

	want := f.Key(key)
	for i := range rules {
		if f.Key(rules[i]) == want {
			return fsutil.WriteJSON(f.Path, append(rules[:i], rules[i+1:]...))
		}
	}
	return fmt.Errorf("no such rule: %s", want)
}

// Best returns the rule score ranks highest among those it accepts (ok),
// the earliest winning ties; ok is false if it accepts none.
func Best[R any](rules []R, score func(R) (int, bool)) (best R, ok bool) {
	top := -1
	for _, rule := range rules {
		if s, accepted := score(rule); accepted && s > top {
			best, top, ok = rule, s, true
		}
	}
	return best, ok
}

// ForReference returns the rule whose match (see match) is the most
// specific segment-boundary prefix of ref's repository (see
// prefix.Repository) — how trust.json and scan.json rules apply to a
// package.
func ForReference[R any](rules []R, ref string, match func(R) string) (R, bool) {
	repository := prefix.Repository(ref)
	return Best(rules, func(r R) (int, bool) {
		return PrefixScore(repository, match(r))
	})
}

// PrefixScore scores a rule's match against address: its number of
// segments (see prefix.Segments) if it matches (see prefix.Matches), so a
// more specific match ranks higher.
func PrefixScore(address, match string) (int, bool) {
	if !prefix.Matches(address, match) {
		return 0, false
	}
	return prefix.Segments(match), true
}

// Display renders a rule field that's empty — matching anything — as "*",
// the way listings and messages show it.
func Display(field string) string {
	if field == "" {
		return "*"
	}
	return field
}

// Users returns an error naming (by match, see Display) every rule that
// uses reports refers to what, a stored item of the given kind, or nil if
// none does — so it can't be removed out from under them.
func Users[R any](rules []R, uses func(R) bool, match func(R) string, what, kind, ruleKind string) error {
	var users []string
	for _, rule := range rules {
		if uses(rule) {
			users = append(users, fmt.Sprintf("%q", Display(match(rule))))
		}
	}
	if len(users) == 0 {
		return nil
	}
	return fmt.Errorf("%s %q is still used by %s rule(s) %s; remove it from them first", kind, what, ruleKind, strings.Join(users, ", "))
}
