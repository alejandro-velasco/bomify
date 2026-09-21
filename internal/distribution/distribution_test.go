package distribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReadMissingFile(t *testing.T) {
	config, err := Read(t.TempDir())
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	if len(config) != 0 {
		t.Fatalf("Read: want empty config, got %v", config)
	}
}

func TestReadParsesRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(ConfigPath(dir)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	const raw = `[
		{"type": "oci", "match": "docker.io/myorg", "endpoint": "registry.example.com"},
		{"type": "helm", "endpoint": "charts.example.com"}
	]`
	if err := os.WriteFile(ConfigPath(dir), []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}

	want := Config{
		{Type: "oci", Match: "docker.io/myorg", Endpoint: "registry.example.com"},
		{Type: "helm", Endpoint: "charts.example.com"},
	}
	if len(config) != len(want) {
		t.Fatalf("Read() = %+v, want %+v", config, want)
	}
	for i := range want {
		if config[i] != want[i] {
			t.Errorf("Read()[%d] = %+v, want %+v", i, config[i], want[i])
		}
	}
}

func TestReadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(ConfigPath(dir)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ConfigPath(dir), []byte("not json"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Read(dir); err == nil {
		t.Fatal("Read: want error for invalid JSON, got nil")
	}
}

// TestReadRejectsOldFlatFormat guards against silently losing every
// pre-rules distribution.json on upgrade: the old "kind -> {endpoint}"
// object must fail to parse as the new Config (a JSON array), not
// silently come back as an empty rule set.
func TestReadRejectsOldFlatFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(ConfigPath(dir)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	const raw = `{"oci": {"endpoint": "local-registry/foo"}}`
	if err := os.WriteFile(ConfigPath(dir), []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Read(dir); err == nil {
		t.Fatal("Read: want error for old flat-object format, got nil")
	}
}

func TestSetRuleWritesNewEntry(t *testing.T) {
	dir := t.TempDir()

	if err := SetRule(dir, "oci", "docker.io/myorg", "registry.example.com"); err != nil {
		t.Fatalf("SetRule: unexpected error: %v", err)
	}

	data, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	want := Config{{Type: "oci", Match: "docker.io/myorg", Endpoint: "registry.example.com"}}
	if len(config) != 1 || config[0] != want[0] {
		t.Errorf("config = %+v, want %+v", config, want)
	}
}

func TestSetRuleMergesWithExisting(t *testing.T) {
	dir := t.TempDir()

	if err := SetRule(dir, "oci", "docker.io/myorg", "registry.example.com"); err != nil {
		t.Fatalf("SetRule (oci): unexpected error: %v", err)
	}
	if err := SetRule(dir, "helm", "", "charts.example.com"); err != nil {
		t.Fatalf("SetRule (helm): unexpected error: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	if len(config) != 2 {
		t.Fatalf("Read() = %+v, want 2 rules", config)
	}
}

func TestSetRuleOverwritesSameTypeAndMatch(t *testing.T) {
	dir := t.TempDir()

	if err := SetRule(dir, "oci", "docker.io/myorg", "old-endpoint"); err != nil {
		t.Fatalf("SetRule: unexpected error: %v", err)
	}
	if err := SetRule(dir, "oci", "docker.io/myorg", "new-endpoint"); err != nil {
		t.Fatalf("SetRule: unexpected error: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	if len(config) != 1 || config[0].Endpoint != "new-endpoint" {
		t.Errorf("config = %+v, want a single rule with endpoint %q", config, "new-endpoint")
	}
}

func TestSetRuleDistinguishesDifferentMatchesForSameType(t *testing.T) {
	dir := t.TempDir()

	if err := SetRule(dir, "oci", "docker.io/myorg", "registry-a.example.com"); err != nil {
		t.Fatalf("SetRule: unexpected error: %v", err)
	}
	if err := SetRule(dir, "oci", "docker.io/otherorg", "registry-b.example.com"); err != nil {
		t.Fatalf("SetRule: unexpected error: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	if len(config) != 2 {
		t.Fatalf("Read() = %+v, want 2 distinct rules", config)
	}
}

func TestRemoveRuleDropsOnlyThatRule(t *testing.T) {
	dir := t.TempDir()

	if err := SetRule(dir, "oci", "docker.io/myorg", "registry-a.example.com"); err != nil {
		t.Fatalf("SetRule: unexpected error: %v", err)
	}
	if err := SetRule(dir, "oci", "docker.io/otherorg", "registry-b.example.com"); err != nil {
		t.Fatalf("SetRule: unexpected error: %v", err)
	}

	if err := RemoveRule(dir, "oci", "docker.io/myorg"); err != nil {
		t.Fatalf("RemoveRule: unexpected error: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	if len(config) != 1 || config[0].Match != "docker.io/otherorg" {
		t.Errorf("config = %+v, want only the docker.io/otherorg rule left", config)
	}
}

func TestRemoveRuleErrorsForUnknownRule(t *testing.T) {
	dir := t.TempDir()

	if err := RemoveRule(dir, "oci", "docker.io/myorg"); err == nil {
		t.Fatal("RemoveRule: want error for a rule that was never set, got nil")
	}
}

// TestResolveNormalizesOriginScheme guards the case a plugin's "remote"
// subcommand reports its Remote with a URL scheme still attached (e.g.
// "oci://registry-1.docker.io/bitnamicharts") — Resolve must still line
// it up against a scheme-less Match.
func TestResolveNormalizesOriginScheme(t *testing.T) {
	rules := Config{{Match: "registry-1.docker.io/bitnamicharts", Endpoint: "mirror"}}

	endpoint, ok := Resolve(rules, "helm", "oci://registry-1.docker.io/bitnamicharts")
	if !ok {
		t.Fatal("Resolve: want a match, got none")
	}
	if endpoint != "mirror" {
		t.Errorf("Resolve() = %q, want %q", endpoint, "mirror")
	}
}

func TestResolvePrefersLongerMatchOverType(t *testing.T) {
	rules := Config{
		{Type: "oci", Endpoint: "type-only"},
		{Match: "docker.io/myorg", Endpoint: "match-only"},
	}

	destination, ok := Resolve(rules, "oci", "docker.io/myorg/myrepo")
	if !ok {
		t.Fatal("Resolve: want a match, got none")
	}
	if want := "match-only/myrepo"; destination != want {
		t.Errorf("Resolve() = %q, want %q (the more specific match wins)", destination, want)
	}
}

func TestResolveUsesTypeAsTiebreaker(t *testing.T) {
	rules := Config{
		{Match: "docker.io/myorg", Endpoint: "untyped"},
		{Type: "oci", Match: "docker.io/myorg", Endpoint: "typed"},
	}

	destination, ok := Resolve(rules, "oci", "docker.io/myorg/myrepo")
	if !ok {
		t.Fatal("Resolve: want a match, got none")
	}
	if want := "typed/myrepo"; destination != want {
		t.Errorf("Resolve() = %q, want %q (equally specific match, typed rule wins the tie)", destination, want)
	}
}

// TestResolveMirrorsRemainderPastMatch is the core correctness test for
// mirror semantics: a matched rule doesn't just select an endpoint, it
// preserves whatever of origin came after the matched prefix — so a rule
// scoped to an org still routes each of that org's repos to its own
// place under the mirror, not all to one shared destination.
func TestResolveMirrorsRemainderPastMatch(t *testing.T) {
	rules := Config{{Type: "oci", Match: "docker.io/myorg", Endpoint: "mirror.example.com"}}

	destination, ok := Resolve(rules, "oci", "docker.io/myorg/sub/repo")
	if !ok {
		t.Fatal("Resolve: want a match, got none")
	}
	if want := "mirror.example.com/sub/repo"; destination != want {
		t.Errorf("Resolve() = %q, want %q", destination, want)
	}
}

// TestResolveMirrorReturnsBareEndpointOnExactMatch guards the case where
// origin doesn't extend past the matched prefix at all: mirror has
// nothing left to append, so it must return Endpoint bare rather than a
// dangling trailing slash.
func TestResolveMirrorReturnsBareEndpointOnExactMatch(t *testing.T) {
	rules := Config{{Match: "docker.io/myorg/repo", Endpoint: "mirror.example.com"}}

	destination, ok := Resolve(rules, "oci", "docker.io/myorg/repo")
	if !ok {
		t.Fatal("Resolve: want a match, got none")
	}
	if destination != "mirror.example.com" {
		t.Errorf("Resolve() = %q, want %q", destination, "mirror.example.com")
	}
}

// TestResolveWildcardRuleDoesNotMirror guards the other half of the
// design: a rule with no Match (type-only or catch-all) is a plain
// lookup, not a mirror — its Endpoint is returned bare even though
// origin is non-empty, since there's no matched prefix to subtract from
// it, and grafting the whole origin on would surprise anyone using a
// rule as a simple fallback.
func TestResolveWildcardRuleDoesNotMirror(t *testing.T) {
	rules := Config{{Type: "oci", Endpoint: "registry.example.com"}}

	destination, ok := Resolve(rules, "oci", "docker.io/library/redis")
	if !ok {
		t.Fatal("Resolve: want a match, got none")
	}
	if destination != "registry.example.com" {
		t.Errorf("Resolve() = %q, want %q (no Match, so nothing to mirror)", destination, "registry.example.com")
	}
}

func TestResolveMatchesAtSegmentBoundaries(t *testing.T) {
	rules := Config{{Match: "docker.io/org", Endpoint: "should-not-match"}}

	if _, ok := Resolve(rules, "oci", "docker.io/organization/repo"); ok {
		t.Error("Resolve: matched \"docker.io/org\" against \"docker.io/organization/repo\", want no match")
	}
}

func TestResolveFallsBackToWildcardRule(t *testing.T) {
	rules := Config{{Endpoint: "catch-all"}}

	endpoint, ok := Resolve(rules, "generic", "example.com/anything")
	if !ok {
		t.Fatal("Resolve: want the wildcard rule to match, got none")
	}
	if endpoint != "catch-all" {
		t.Errorf("Resolve() = %q, want %q", endpoint, "catch-all")
	}
}

func TestResolveNoMatch(t *testing.T) {
	rules := Config{{Type: "helm", Endpoint: "charts.example.com"}}

	if _, ok := Resolve(rules, "oci", "docker.io/myorg"); ok {
		t.Error("Resolve: want no match for an unconfigured type, got one")
	}
}
