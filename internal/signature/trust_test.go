package signature

import (
	"reflect"
	"testing"
)

func TestResolve(t *testing.T) {
	rules := Config{
		{Match: "", Verifier: "catchall"},
		{Match: "registry.example.com", Verifier: "registry"},
		{Match: "registry.example.com/team", Verifier: "team"},
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
		if !ok || rule.Verifier != tt.want {
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
		Rules:    Config{{Match: "registry.example.com", Verifier: "rule"}},
	}

	p, ok := policy.For("registry.example.com/app:v1", discardLogger())
	if !ok || !reflect.DeepEqual(p, policy.Verifier) {
		t.Errorf("For = %+v, %v; want the explicit verifier", p, ok)
	}
}

func TestSetAndRemoveRule(t *testing.T) {
	baseDir := t.TempDir()

	if err := SetRule(baseDir, "registry.example.com", "sigstore", []string{"key=a.pub"}); err != nil {
		t.Fatal(err)
	}
	if err := SetRule(baseDir, "", "sigstore", nil); err != nil {
		t.Fatal(err)
	}
	// Re-setting an existing match replaces it rather than appending.
	if err := SetRule(baseDir, "registry.example.com", "notation", []string{"key=b.pub"}); err != nil {
		t.Fatal(err)
	}

	config, err := Read(baseDir)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		{Match: "registry.example.com", Verifier: "notation", Options: []string{"key=b.pub"}},
		{Match: "", Verifier: "sigstore"},
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

func TestReadMissingConfig(t *testing.T) {
	config, err := Read(t.TempDir())
	if err != nil || len(config) != 0 {
		t.Errorf("Read = %+v, %v; want empty, nil", config, err)
	}
}
