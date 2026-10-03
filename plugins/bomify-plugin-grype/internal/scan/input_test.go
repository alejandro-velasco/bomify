package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestInputWithNothingToCatalog scans files syft finds no package in:
// the component is reported as not analyzed, not as clean. No
// vulnerability database is needed, since nothing is matched.
func TestInputWithNothingToCatalog(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("Hello World!\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Input(nil, dir)
	if err != nil {
		t.Fatalf("Input: %v", err)
	}
	if result.Unscanned == "" || len(result.Vulnerabilities) != 0 {
		t.Errorf("Input = %+v, want it reported unscanned", result)
	}
}

// TestCatalogFilesFindsGoBinary builds a small Go binary and catalogs the
// directory holding it: syft reads the module list Go embeds in every
// binary, so the binary's own module and the standard library show up.
func TestCatalogFilesFindsGoBinary(t *testing.T) {
	src := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.com/catalogme\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "catalogme")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	packages, _, err := catalogFiles(dir)
	if err != nil {
		t.Fatalf("catalogFiles: %v", err)
	}
	found := map[string]bool{}
	for _, p := range packages {
		found[p.Name] = true
	}
	for _, want := range []string{"example.com/catalogme", "stdlib"} {
		if !found[want] {
			t.Errorf("cataloged %v, want %s among them", found, want)
		}
	}
}
