package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/build"
)

// TestLoadQuiet covers "bomify load --quiet": stdout carries nothing but
// one pinned reference per tag in the archive, and the tags are still
// restored exactly as without --quiet.
func TestLoadQuiet(t *testing.T) {
	sourceDir := newDataDir(t)
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sbomHash, _, err := build.RecordManifest(sourceDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	if err := build.UpdateRepositories(sourceDir, []string{"registry.example.com/team/app:v1"}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, sourceDir, "save", "registry.example.com/team/app:v1", "--output", archive); err != nil {
		t.Fatalf("save: %v", err)
	}

	destDir := newDataDir(t)
	out, err := runRootCmd(t, destDir, "load", "--input", archive, "--quiet")
	if err != nil {
		t.Fatalf("load --quiet: %v", err)
	}

	want := regexp.MustCompile(`^registry\.example\.com/team/app@sha256:[0-9a-f]{64}$`)
	if got := strings.TrimSpace(out); !want.MatchString(got) {
		t.Errorf("load --quiet printed %q, want exactly <repository>@<digest>", out)
	}
	if _, err := build.ResolveTag(destDir, "registry.example.com/team/app:v1"); err != nil {
		t.Errorf("load --quiet didn't restore the tag: %v", err)
	}

	// Without --quiet, the same archive reports the tag as before.
	out, err = runRootCmd(t, newDataDir(t), "load", "--input", archive)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if strings.TrimSpace(out) != "Loaded: registry.example.com/team/app:v1" {
		t.Errorf("load printed %q", out)
	}
}
