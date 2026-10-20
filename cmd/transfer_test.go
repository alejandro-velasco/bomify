package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// TestSavePacksWithComponentPlugins covers how save, as push, packages
// each component: with its plugin's "component pack", so the plugin must
// be installed.
func TestSavePacksWithComponentPlugins(t *testing.T) {
	baseDir := newDataDir(t)
	writePackage(t, baseDir, hookTag, hookComponent)
	layerDir := layout.ComponentLayer(baseDir, hookComponent.PackageURL)
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "artifact"), []byte("contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "app.tar")

	_, err := runRootCmd(t, baseDir, "save", hookTag, "--output", archive)
	if err == nil || !strings.Contains(err.Error(), `"bomify-plugin-generic" is not installed`) {
		t.Fatalf("save without the component's plugin = %v, want an error naming it", err)
	}

	testutil.InstallFakePlugin(t, layout.Plugins(baseDir), "generic")
	if _, err := runRootCmd(t, baseDir, "save", hookTag, "--output", archive); err != nil {
		t.Fatalf("save with the component's plugin: %v", err)
	}
}
