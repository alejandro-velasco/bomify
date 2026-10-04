package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// buildFakePluginBinary installs the fake plugin as
// bomify-plugin-<medium> into a fresh data directory's plugins
// directory, for plugin.Find to discover there, and returns that data
// directory.
func buildFakePluginBinary(t *testing.T, medium string) string {
	t.Helper()
	dir := t.TempDir()
	testutil.InstallFakePlugin(t, layout.Plugins(dir), medium)
	return dir
}

// useDataDir makes dir the data directory NewRootCmd defaults to, since
// "sbom generate" passes every flag after it — --data-dir included —
// straight through to the plugin.
func useDataDir(t *testing.T, dir string) {
	t.Helper()

	origDataDir := dataDir
	t.Cleanup(func() { dataDir = origDataDir })
	dataDir = ""
	t.Setenv(layout.DataDirEnv, dir)
}

func TestSBOMGenerateDelegatesToPlugin(t *testing.T) {
	useDataDir(t, buildFakePluginBinary(t, "helm"))

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
	useDataDir(t, buildFakePluginBinary(t, "helm"))

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

// TestSBOMGenerateHonorsDataDir covers --data-dir given before <medium>,
// either side of "sbom generate": bomify parses it (it decides which
// plugins directory the plugin is found in), and it never reaches the
// plugin itself, while everything after <medium> still does.
func TestSBOMGenerateHonorsDataDir(t *testing.T) {
	baseDir := buildFakePluginBinary(t, "helm")
	useDataDir(t, t.TempDir())

	for _, args := range [][]string{
		{"--data-dir", baseDir, "sbom", "generate", "helm", "--chart", "x"},
		{"sbom", "generate", "--data-dir=" + baseDir, "--verbose", "helm", "--chart", "x"},
	} {
		dataDir = ""
		root, err := NewRootCmd()
		if err != nil {
			t.Fatalf("NewRootCmd: %v", err)
		}

		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		root.SetArgs(args)

		if err := root.Execute(); err != nil {
			t.Fatalf("%v: Execute() error = %v, stderr = %s", args, err, stderr.String())
		}
		if got, want := strings.TrimSpace(stdout.String()), "sbom generate --chart x"; got != want {
			t.Errorf("%v: stdout = %q, want %q", args, got, want)
		}
	}
}

// TestSBOMGeneratePassesHelpThrough covers --help after <medium>: it's
// the plugin's to answer, not bomify's.
func TestSBOMGeneratePassesHelpThrough(t *testing.T) {
	useDataDir(t, buildFakePluginBinary(t, "helm"))

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"sbom", "generate", "helm", "--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr = %s", err, stderr.String())
	}
	if got, want := strings.TrimSpace(stdout.String()), "sbom generate --help"; got != want {
		t.Errorf("stdout = %q, want %q (the plugin's, not bomify's, help)", got, want)
	}
}

func TestSBOMGenerateRejectsUnknownFlagBeforeMedium(t *testing.T) {
	useDataDir(t, t.TempDir())

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"sbom", "generate", "--chart", "x", "helm"})

	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "unknown flag: --chart") {
		t.Fatalf("Execute() error = %v, want an unknown flag error for --chart before <medium>", err)
	}
}

func TestSBOMGenerateMissingPlugin(t *testing.T) {
	useDataDir(t, t.TempDir())

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
