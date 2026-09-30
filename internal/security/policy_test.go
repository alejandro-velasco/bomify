package security

import (
	"testing"
)

func TestResolve(t *testing.T) {
	rules := Config{
		{Match: "", Scanner: "catchall"},
		{Match: "registry.example.com", Scanner: "registry"},
		{Match: "registry.example.com/team", Scanner: "team", FailOn: "high"},
	}

	for _, tt := range []struct {
		ref, want string
	}{
		{"registry.example.com/team/app:v1", "team"},
		{"registry.example.com/team@sha256:abcd", "team"},
		{"registry.example.com/teamwork/app:v1", "registry"},
		{"other.example.com/app:v1", "catchall"},
		{"myapp:v1", "catchall"},
	} {
		rule, ok := Resolve(rules, tt.ref)
		if !ok || rule.Scanner != tt.want {
			t.Errorf("Resolve(%q) = %+v, %v; want %s", tt.ref, rule, ok, tt.want)
		}
	}

	if _, ok := Resolve(rules[1:], "myapp:v1"); ok {
		t.Error("Resolve() matched with no applicable rule")
	}
}

func TestSetAndRemoveRule(t *testing.T) {
	baseDir := t.TempDir()

	if config, err := ReadConfig(baseDir); err != nil || len(config) != 0 {
		t.Fatalf("ReadConfig(missing) = %v, %v; want empty", config, err)
	}

	if err := SetRule(baseDir, Rule{Match: "registry.example.com", Scanner: "grype", FailOn: "high"}); err != nil {
		t.Fatalf("SetRule: %v", err)
	}
	if err := SetRule(baseDir, Rule{Match: "registry.example.com", Scanner: "grype", FailOn: "critical"}); err != nil {
		t.Fatalf("SetRule (replace): %v", err)
	}
	if err := SetRule(baseDir, Rule{Scanner: "grype", FailOn: "severe"}); err == nil {
		t.Error("SetRule accepted an invalid --fail-on")
	}

	config, err := ReadConfig(baseDir)
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if len(config) != 1 || config[0].FailOn != "critical" {
		t.Fatalf("config = %+v, want the one replaced rule", config)
	}

	g, err := config[0].Gate()
	if err != nil || g.FailOn != SeverityCritical {
		t.Errorf("Gate() = %+v, %v", g, err)
	}

	if err := RemoveRule(baseDir, "registry.example.com"); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if err := RemoveRule(baseDir, "registry.example.com"); err == nil {
		t.Error("RemoveRule of a missing rule succeeded")
	}
}
