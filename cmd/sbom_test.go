package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildFakePluginBinary builds cmd/testdata/fakeplugin as
// bomify-plugin-<medium>[.exe] into a fresh temp directory and returns
// that directory, so the caller can put it on PATH for plugin.Find to
// discover.
func buildFakePluginBinary(t *testing.T, medium string) string {
	t.Helper()

	dir := t.TempDir()
	bin := filepath.Join(dir, "bomify-plugin-"+medium)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	build := exec.Command("go", "build", "-o", bin, "./testdata/fakeplugin")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake plugin: %v\n%s", err, out)
	}

	return dir
}

func TestSBOMGenerateDelegatesToPlugin(t *testing.T) {
	dir := buildFakePluginBinary(t, "helm")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"sbom", "generate", "helm", "--chart", "postgresql"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}

	// The fake plugin echoes its own args verbatim: bomify must have
	// exec'd it as "sbom generate --chart postgresql" (medium consumed,
	// everything after it passed through unchanged).
	want := "sbom generate --chart postgresql"
	if got := strings.TrimSpace(stdout.String()); got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestSBOMGeneratePropagatesPluginFailure(t *testing.T) {
	dir := buildFakePluginBinary(t, "helm")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"sbom", "generate", "helm", "--fail"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want an error from the failing plugin")
	}
}

func TestSBOMGenerateMissingPlugin(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"sbom", "generate", "does-not-exist"})

	if err := root.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want an error for a missing plugin")
	}
}
