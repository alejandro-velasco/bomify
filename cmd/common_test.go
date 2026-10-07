package cmd

import (
	"sort"
	"testing"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
)

// newDataDir returns an empty data directory at the current version, so
// a test can seed it before running a command, which refuses a
// non-empty one with no version.
func newDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := layout.CheckVersion(dir); err != nil {
		t.Fatalf("version data directory: %v", err)
	}
	return dir
}

func TestResolvedDataDirPrefersDataDirFlag(t *testing.T) {
	c := &cobra.Command{}
	c.Flags().String("data-dir", "", "")
	if err := c.Flags().Set("data-dir", "/explicit"); err != nil {
		t.Fatalf("set data-dir flag: %v", err)
	}

	if got := resolvedDataDir(c); got != "/explicit" {
		t.Errorf("resolvedDataDir() = %q, want %q", got, "/explicit")
	}
}

func TestResolvedDataDirFallsBackWithoutFlag(t *testing.T) {
	c := &cobra.Command{}
	c.Flags().String("data-dir", "", "")

	if got := resolvedDataDir(c); got == "" {
		t.Error("resolvedDataDir() = \"\", want a non-empty default")
	}
}

func TestCompleteLocalTagsListsAndFilters(t *testing.T) {
	dir := t.TempDir()
	if err := build.UpdateRepositories(dir, []string{"myapp:1.0", "myapp:latest", "otherapp:2.0"}, "somehash"); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	c := &cobra.Command{}
	c.Flags().String("data-dir", "", "")
	if err := c.Flags().Set("data-dir", dir); err != nil {
		t.Fatalf("set data-dir flag: %v", err)
	}

	tags, directive := completeLocalTags(c, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want ShellCompDirectiveNoFileComp", directive)
	}
	sort.Strings(tags)
	want := []string{"myapp:1.0", "myapp:latest", "otherapp:2.0"}
	if !equalSlices(tags, want) {
		t.Errorf("completeLocalTags(\"\") = %v, want %v", tags, want)
	}

	filtered, _ := completeLocalTags(c, nil, "myapp")
	sort.Strings(filtered)
	wantFiltered := []string{"myapp:1.0", "myapp:latest"}
	if !equalSlices(filtered, wantFiltered) {
		t.Errorf("completeLocalTags(\"myapp\") = %v, want %v", filtered, wantFiltered)
	}
}

func TestCompleteLocalTagsMissingRepositories(t *testing.T) {
	c := &cobra.Command{}
	c.Flags().String("data-dir", "", "")
	if err := c.Flags().Set("data-dir", t.TempDir()); err != nil {
		t.Fatalf("set data-dir flag: %v", err)
	}

	tags, directive := completeLocalTags(c, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want ShellCompDirectiveNoFileComp", directive)
	}
	if len(tags) != 0 {
		t.Errorf("completeLocalTags() with no repositories.json = %v, want empty", tags)
	}
}

func TestCompleteSourceTagOffersNothingForSecondArg(t *testing.T) {
	c := &cobra.Command{}
	c.Flags().String("data-dir", "", "")
	if err := c.Flags().Set("data-dir", t.TempDir()); err != nil {
		t.Fatalf("set data-dir flag: %v", err)
	}

	tags, directive := completeSourceTag(c, []string{"myapp:1.0"}, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("directive = %v, want ShellCompDirectiveNoFileComp", directive)
	}
	if len(tags) != 0 {
		t.Errorf("completeSourceTag() for the destination arg = %v, want empty", tags)
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
