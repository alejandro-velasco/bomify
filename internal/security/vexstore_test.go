package security

import (
	"os"
	"testing"
)

const storeDoc = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"x","timestamp":"2026-01-01T00:00:00Z",
	"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"fixed"}]}`

func TestVEXStore(t *testing.T) {
	baseDir := t.TempDir()
	src := writeVEX(t, "team.json", storeDoc)

	first, err := AddVEX(baseDir, "team", src)
	if err != nil {
		t.Fatalf("AddVEX: %v", err)
	}
	if _, err := os.Stat(VEXPath(baseDir, first.SHA256)); err != nil {
		t.Fatalf("stored copy missing: %v", err)
	}

	// The same content under a second name shares one stored copy.
	if _, err := AddVEX(baseDir, "alias", src); err != nil {
		t.Fatalf("AddVEX (second name): %v", err)
	}

	// Editing the source changes nothing until it's added again.
	if err := os.WriteFile(src, []byte(storeDoc+" "), 0o644); err != nil {
		t.Fatalf("edit source: %v", err)
	}
	paths, err := ResolveVEX(baseDir, []string{"team"})
	if err != nil || len(paths) != 1 || paths[0] != VEXPath(baseDir, first.SHA256) {
		t.Fatalf("ResolveVEX = %v, %v; want the original copy", paths, err)
	}

	// Re-adding replaces it; the old copy stays while "alias" uses it.
	second, err := AddVEX(baseDir, "team", src)
	if err != nil || second.SHA256 == first.SHA256 {
		t.Fatalf("re-AddVEX = %+v, %v; want new content", second, err)
	}
	if _, err := os.Stat(VEXPath(baseDir, first.SHA256)); err != nil {
		t.Errorf("copy still used by alias was deleted: %v", err)
	}

	entries, err := ListVEX(baseDir)
	if err != nil || len(entries) != 2 || entries[0].Name != "alias" || entries[1].Name != "team" {
		t.Fatalf("ListVEX = %+v, %v; want alias and team, sorted", entries, err)
	}

	// Removing the last name using a copy deletes it.
	if err := RemoveVEX(baseDir, "alias"); err != nil {
		t.Fatalf("RemoveVEX: %v", err)
	}
	if _, err := os.Stat(VEXPath(baseDir, first.SHA256)); !os.IsNotExist(err) {
		t.Errorf("unreferenced copy kept: err = %v", err)
	}

	if _, err := ResolveVEX(baseDir, []string{"alias"}); err == nil {
		t.Error("ResolveVEX of a removed name succeeded")
	}
}

func TestRemoveVEXRefusesWhileRuleUsesIt(t *testing.T) {
	baseDir := t.TempDir()
	if _, err := AddVEX(baseDir, "team", writeVEX(t, "team.json", storeDoc)); err != nil {
		t.Fatalf("AddVEX: %v", err)
	}
	if err := SetRule(baseDir, Rule{Scanners: []string{"grype"}, FailOn: "high", VEX: []string{"team"}}); err != nil {
		t.Fatalf("SetRule: %v", err)
	}
	if err := SetRule(baseDir, Rule{Match: "x", Scanners: []string{"grype"}, VEX: []string{"missing"}}); err == nil {
		t.Error("SetRule accepted an unknown VEX name")
	}
	if err := RemoveVEX(baseDir, "team"); err == nil {
		t.Error("RemoveVEX of a document a rule uses succeeded")
	}
}

func TestAddVEXRejectsBadInput(t *testing.T) {
	baseDir := t.TempDir()
	good := writeVEX(t, "good.json", storeDoc)
	for name, args := range map[string][2]string{
		"empty name":   {"", good},
		"comma name":   {"a,b", good},
		"flag name":    {"-x", good},
		"not VEX":      {"x", writeVEX(t, "spdx.json", `{"spdxVersion":"SPDX-2.3"}`)},
		"missing file": {"x", good + ".missing"},
	} {
		if _, err := AddVEX(baseDir, args[0], args[1]); err == nil {
			t.Errorf("%s: AddVEX error = nil, want one", name)
		}
	}
	if entries, _ := ListVEX(baseDir); len(entries) != 0 {
		t.Errorf("rejected adds left entries: %+v", entries)
	}
}
