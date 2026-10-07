package signature

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"
)

// one is a rule's signers when it has just one, unnamed, as "bomify trust
// create" makes it without --signer.
func one(verifier string, options ...string) []Signer {
	return []Signer{{Kind: verifier, Options: options}}
}

func TestResolve(t *testing.T) {
	rules := Config{
		{Match: "", Signers: one("catchall")},
		{Match: "registry.example.com", Signers: one("registry")},
		{Match: "registry.example.com/team", Signers: one("team")},
	}

	tests := []struct {
		ref, want string
	}{
		{"registry.example.com/team/app:v1", "team"},
		{"registry.example.com/teamwork/app:v1", "registry"},
		{"registry.example.com/app:v1", "registry"},
		{"other.example.com/app:v1", "catchall"},
		{"myapp:v1", "catchall"},
	}
	for _, tt := range tests {
		rule, ok := Resolve(rules, tt.ref)
		if !ok || rule.Signers[0].Kind != tt.want {
			t.Errorf("Resolve(%q) = %+v, %v; want verifier %q", tt.ref, rule, ok, tt.want)
		}
	}

	if _, ok := Resolve(rules[1:], "other.example.com/app:v1"); ok {
		t.Error("Resolve matched a reference no rule covers")
	}
}

func TestPolicyFlagOverridesRules(t *testing.T) {
	policy := Policy{
		Verifier: Plugin{Kind: "flag", Options: []string{"key=a"}},
		Rules:    Config{{Match: "registry.example.com", Signers: one("rule")}},
	}

	req, ok := policy.For("registry.example.com/app:v1")
	want := Requirement{Signers: []Signer{{Kind: "flag", Options: []string{"key=a"}}}}
	if !ok || !reflect.DeepEqual(req, want) {
		t.Errorf("For = %+v, %v; want just the explicit verifier", req, ok)
	}
}

func TestPolicyRuleRequirement(t *testing.T) {
	signers := []Signer{{Name: "release", Kind: "sigstore"}, {Name: "security", Kind: "sigstore"}}
	policy := Policy{Rules: Config{{Match: "registry.example.com", Signers: signers, Require: 1}}}

	req, ok := policy.For("registry.example.com/app:v1")
	if !ok || !reflect.DeepEqual(req, Requirement{Signers: signers, Require: 1}) {
		t.Errorf("For = %+v, %v; want the rule's signers and Require", req, ok)
	}
	if got := req.required(); got != 1 {
		t.Errorf("required = %d, want 1", got)
	}
	if got := (Requirement{Signers: signers}).required(); got != 2 {
		t.Errorf("required with Require 0 = %d, want every signer", got)
	}
}

func TestSetAndRemoveRule(t *testing.T) {
	baseDir := t.TempDir()

	if err := SetRule(baseDir, Rule{Match: "registry.example.com", Signers: one("sigstore", "key=a.pub")}); err != nil {
		t.Fatal(err)
	}
	if err := SetRule(baseDir, Rule{Signers: one("sigstore")}); err != nil {
		t.Fatal(err)
	}
	// Re-setting an existing match replaces it rather than appending.
	if err := SetRule(baseDir, Rule{Match: "registry.example.com", Signers: one("notation", "key=b.pub")}); err != nil {
		t.Fatal(err)
	}

	config, err := Read(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		{Match: "registry.example.com", Signers: one("notation", "key=b.pub")},
		{Match: "", Signers: one("sigstore")},
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("config = %+v, want %+v", config, want)
	}

	if err := RemoveRule(baseDir, "registry.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRule(baseDir, "registry.example.com"); err == nil {
		t.Error("RemoveRule of a missing rule: nil, want error")
	}

	config, err = Read(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(config) != 1 || config[0].Match != "" {
		t.Errorf("config after remove = %+v, want just the catch-all", config)
	}
}

func TestSetRuleRejectsInvalid(t *testing.T) {
	two := []Signer{{Name: "a", Kind: "sigstore"}, {Name: "b", Kind: "sigstore"}}
	for _, tc := range []struct {
		name string
		rule Rule
		want string
	}{
		{"no signers", Rule{}, "no signers"},
		{"two unnamed signers", Rule{Signers: []Signer{{Kind: "sigstore"}, {Kind: "notation"}}}, "the unnamed signer: given more than once"},
		{"no plugin", Rule{Signers: []Signer{{Name: "a"}}}, "no plugin"},
		{"duplicate names", Rule{Signers: []Signer{two[0], two[0]}}, "more than once"},
		{"require too many", Rule{Signers: two, Require: 3}, "requires 3 signers but has 2"},
		{"negative require", Rule{Signers: two, Require: -1}, "requires -1"},
	} {
		if err := SetRule(t.TempDir(), tc.rule); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: SetRule = %v, want an error containing %q", tc.name, err, tc.want)
		}
	}
}

func TestUpdateRuleAddsSigners(t *testing.T) {
	baseDir := t.TempDir()
	add := func(s Signer, update func(*Rule)) {
		t.Helper()
		err := UpdateRule(baseDir, "registry.example.com", func(r *Rule) {
			r.SetSigner(s)
			if update != nil {
				update(r)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	add(Signer{Name: "release", Kind: "sigstore", Options: []string{"key=r.pub"}}, func(r *Rule) { r.Provenance = true })
	add(Signer{Name: "security", Kind: "sigstore", Options: []string{"key=s.pub"}}, func(r *Rule) { r.Require = 1 })
	// Replacing a signer keeps the rule's other signers and settings.
	add(Signer{Name: "release", Kind: "sigstore", Options: []string{"key=r2.pub"}}, nil)

	config, err := Read(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{{
		Match: "registry.example.com",
		Signers: []Signer{
			{Name: "release", Kind: "sigstore", Options: []string{"key=r2.pub"}},
			{Name: "security", Kind: "sigstore", Options: []string{"key=s.pub"}},
		},
		Require:    1,
		Provenance: true,
	}}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("config = %+v, want %+v", config, want)
	}
}

func TestRemoveSigner(t *testing.T) {
	baseDir := t.TempDir()
	rule := Rule{Match: "m", Signers: []Signer{{Name: "a", Kind: "x"}, {Name: "b", Kind: "x"}, {Name: "c", Kind: "x"}}, Require: 2}
	if err := SetRule(baseDir, rule); err != nil {
		t.Fatal(err)
	}

	if err := RemoveSigner(baseDir, "m", "missing"); err == nil {
		t.Error("RemoveSigner of a missing signer: nil, want error")
	}
	if err := RemoveSigner(baseDir, "other", "a"); err == nil {
		t.Error("RemoveSigner from a missing rule: nil, want error")
	}
	if err := RemoveSigner(baseDir, "m", "a"); err != nil {
		t.Fatal(err)
	}
	// Two signers left, both required: removing either would leave fewer
	// signers than the rule requires.
	if err := RemoveSigner(baseDir, "m", "b"); err == nil || !strings.Contains(err.Error(), "requires 2 signers but has 1") {
		t.Errorf("RemoveSigner below Require = %v, want an error", err)
	}

	if err := SetRule(baseDir, Rule{Match: "m", Signers: []Signer{{Name: "b", Kind: "x"}}}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSigner(baseDir, "m", "b"); err != nil {
		t.Fatal(err)
	}
	if config, err := Read(baseDir); err != nil || len(config) != 0 {
		t.Errorf("config after removing the last signer = %+v, %v; want the rule gone", config, err)
	}
}

// TestUnnamedSignerStays covers the caveat "bomify trust create"
// documents: a rule created without --signer keeps that unnamed signer
// when named ones are added, so all of them are required, until it's
// removed by its empty name.
func TestUnnamedSignerStays(t *testing.T) {
	baseDir := t.TempDir()
	for _, s := range []Signer{{Kind: "sigstore"}, {Name: "security", Kind: "sigstore"}} {
		if err := UpdateRule(baseDir, "m", func(r *Rule) { r.SetSigner(s) }); err != nil {
			t.Fatal(err)
		}
	}
	config, err := Read(baseDir)
	if err != nil || len(config) != 1 || len(config[0].Signers) != 2 || config[0].Required() != 2 {
		t.Fatalf("config = %+v, %v; want one rule requiring both signers", config, err)
	}

	if err := RemoveSigner(baseDir, "m", ""); err != nil {
		t.Fatalf("RemoveSigner of the unnamed signer: %v", err)
	}
	config, err = Read(baseDir)
	if err != nil || len(config[0].Signers) != 1 || config[0].Signers[0].Name != "security" {
		t.Errorf("config = %+v, %v; want just the security signer", config, err)
	}
	if err := RemoveSigner(baseDir, "m", ""); err == nil || !strings.Contains(err.Error(), `the unnamed signer: not in trust rule "m"`) {
		t.Errorf("RemoveSigner of a missing unnamed signer = %v, want an error naming it", err)
	}
}

func TestSignerError(t *testing.T) {
	cause := errors.New("no signature found")
	for _, tc := range []struct {
		name, want string
	}{
		{"release", `signer "release": no signature found`},
		{"", "the unnamed signer: no signature found"},
	} {
		err := error(&SignerError{Name: tc.name, Err: cause})
		if err.Error() != tc.want {
			t.Errorf("Error() = %q, want %q", err.Error(), tc.want)
		}
		var signerErr *SignerError
		if !errors.As(err, &signerErr) || signerErr.Name != tc.name || !errors.Is(err, cause) {
			t.Errorf("%q: errors.As/Is don't see the signer and its cause", tc.name)
		}
	}
}

// TestReadResolvedRejectsInvalid covers rules that would verify less than
// written: they fail rather than restore matching packages unverified.
func TestReadResolvedRejectsInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		want    string
	}{
		"hand-edited to no signers": {
			content: `[{"match":"registry.example.com","signers":[]}]`,
			want:    "no signers",
		},
		// Written before rules had signers; no longer read.
		"old single-verifier format": {
			content: `[{"match":"registry.example.com","verifier":"sigstore","options":["key=a.pub"]}]`,
			want:    `unknown field "verifier"`,
		},
		// Would otherwise drop the provenance requirement.
		"misspelled field": {
			content: `[{"match":"registry.example.com","signers":[{"plugin":"sigstore"}],"provenence":true}]`,
			want:    `unknown field "provenence"`,
		},
	} {
		baseDir := t.TempDir()
		path := layout.TrustConfig(baseDir)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadResolved(baseDir); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ReadResolved = %v, want an error containing %q", name, err, tc.want)
		}
	}
}

func TestReadMissingConfig(t *testing.T) {
	config, err := Read(t.TempDir())
	if err != nil || len(config) != 0 {
		t.Errorf("Read = %+v, %v; want empty, nil", config, err)
	}
}

func TestPolicyProvenanceRequired(t *testing.T) {
	rules := Config{
		{Match: "registry.example.com", Signers: one("rule"), Provenance: true},
		{Match: "registry.example.com/legacy", Signers: one("rule")},
	}
	for _, tc := range []struct {
		name   string
		policy Policy
		ref    string
		want   bool
	}{
		{"rule requires it", Policy{Rules: rules}, "registry.example.com/app:1", true},
		{"more specific rule doesn't", Policy{Rules: rules}, "registry.example.com/legacy/app:1", false},
		{"no rule matches", Policy{Rules: rules}, "other.example.com/app:1", false},
		{"flag requires it", Policy{Rules: rules, Provenance: true}, "other.example.com/app:1", true},
		{"--verify ignores rules", Policy{Rules: rules, Verifier: Plugin{Kind: "flag"}}, "registry.example.com/app:1", false},
		{"--verify with the flag", Policy{Verifier: Plugin{Kind: "flag"}, Provenance: true}, "registry.example.com/app:1", true},
		{"skip", Policy{Rules: rules, Skip: true}, "registry.example.com/app:1", false},
	} {
		if got := tc.policy.ProvenanceRequired(tc.ref); got != tc.want {
			t.Errorf("%s: ProvenanceRequired = %v, want %v", tc.name, got, tc.want)
		}
	}
}
