// Package testutil holds helpers shared by tests across packages.
package testutil

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// InstallFakePlugin builds internal/testutil/fakeplugin — a stand-in
// implementing every plugin contract — into dir as bomify-plugin-<kind>
// (plus ".exe" on Windows, as plugin.ExecutableName names it; not called
// here, so internal/plugin's own tests can use this), and returns its
// path.
func InstallFakePlugin(t testing.TB, dir, kind string) string {
	t.Helper()

	name := "bomify-plugin-" + kind
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(dir, name)
	build := exec.Command("go", "build", "-o", bin, "github.com/alejandro-velasco/bomify/internal/testutil/fakeplugin")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fake plugin: %v\n%s", err, out)
	}
	return bin
}
