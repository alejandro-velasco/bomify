package cmd

import (
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
	dir := newDataDir(t)
	testutil.InstallFakePlugin(t, layout.Plugins(dir), medium)
	return dir
}

// useDataDir makes dir the data directory NewRootCmd defaults to.
func useDataDir(t *testing.T, dir string) {
	t.Helper()

	origDataDir := dataDir
	t.Cleanup(func() { dataDir = origDataDir })
	dataDir = ""
	t.Setenv(layout.DataDirEnv, dir)
}
