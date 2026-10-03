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
	return installPlugin(t, dir, kind, "fakeplugin")
}

// InstallLibPlugin builds internal/testutil/libplugin — a plugin built
// with pkg/plugin's command builders — into dir as bomify-plugin-<kind>,
// as InstallFakePlugin does, and returns its path.
func InstallLibPlugin(t testing.TB, dir, kind string) string {
	t.Helper()
	return installPlugin(t, dir, kind, "libplugin")
}

// installPlugin builds internal/testutil/<pkg> into dir as
// bomify-plugin-<kind>, returning its path.
func installPlugin(t testing.TB, dir, kind, pkg string) string {
	t.Helper()

	name := "bomify-plugin-" + kind
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(dir, name)
	build := exec.Command("go", "build", "-o", bin, "github.com/alejandro-velasco/bomify/internal/testutil/"+pkg)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	return bin
}
