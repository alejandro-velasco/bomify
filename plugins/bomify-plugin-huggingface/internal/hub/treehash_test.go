package hub

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTreeHashMatchesSha256sum pins TreeHash to the documented command,
// whose output for these files was computed with GNU coreutils:
//
//	find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --text | sha256sum
//
// "dir-c.txt" sorts before "dir/b.bin", since "-" sorts before "/".
func TestTreeHashMatchesSha256sum(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"a.txt":     "a\n",
		"dir/b.bin": "b",
		"dir-c.txt": "c",
	})

	hash, paths, err := TreeHash(dir)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if want := "aabe8c24308b08c7e21fb785288d5e34a5d706b8a04640fed7c5f26934931beb"; hash != want {
		t.Errorf("hash = %s, want %s", hash, want)
	}
	if want := []string{"a.txt", "dir-c.txt", "dir/b.bin"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

func TestTreeHashRejectsBackslash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, `a\b`)
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		// Windows can't name a file with a backslash at all.
		t.Skipf("can't create %q: %v", path, err)
	}

	if _, _, err := TreeHash(dir); err == nil || !strings.Contains(err.Error(), "backslash") {
		t.Errorf("TreeHash = %v, want the backslash rejected", err)
	}
}
