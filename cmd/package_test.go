package cmd

import "testing"

func TestPackageCmdHasVerbAliases(t *testing.T) {
	pkg := packageCmd()

	want := map[string]string{
		"build":      "build <sbom-file>",
		"push":       "push <tag>",
		"pull":       "pull <reference>",
		"tag":        "tag <source-tag> <destination-tag>",
		"save":       "save <tag>...",
		"load":       "load",
		"distribute": "distribute <tag>",
	}

	for name, wantUse := range want {
		c, _, err := pkg.Find([]string{name})
		if err != nil {
			t.Errorf("bomify package %s: not found: %v", name, err)
			continue
		}
		if c.Use != wantUse {
			t.Errorf("bomify package %s: Use = %q, want %q", name, c.Use, wantUse)
		}
		if c.RunE == nil {
			t.Errorf("bomify package %s: RunE is nil", name)
		}
	}
}

func TestPackageCmdAliasesShareFlagsWithTopLevel(t *testing.T) {
	pkg := packageCmd()

	aliased, _, err := pkg.Find([]string{"push"})
	if err != nil {
		t.Fatalf("bomify package push: not found: %v", err)
	}
	if aliased.Flags().Lookup("concurrency") == nil {
		t.Error("bomify package push: missing --concurrency flag from the top-level push command")
	}
	if aliased.ValidArgsFunction == nil {
		t.Error("bomify package push: missing ValidArgsFunction (tag completion) from the top-level push command")
	}
}
