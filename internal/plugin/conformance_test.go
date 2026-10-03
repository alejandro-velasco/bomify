package plugin

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/testutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// TestCallsParseWithPkgPlugin makes every component contract call bomify
// makes, plus the contract version check, against a plugin built with
// pkg/plugin's builders (see testutil.InstallLibPlugin), so an argument
// bomify passes that they don't accept — an unknown or missing flag —
// fails here rather than in a real plugin.
func TestCallsParseWithPkgPlugin(t *testing.T) {
	dir := t.TempDir()
	bin := testutil.InstallLibPlugin(t, dir, "lib")
	baseDir := t.TempDir()
	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}
	const remote = "registry.example.com/mirror"

	if _, err := Find(dir, "lib", pluginlib.ComponentContract); err != nil {
		t.Errorf("Find: %v", err)
	}
	if _, err := CheckPull(bin, component, baseDir, testLogger()); err != nil {
		t.Errorf("CheckPull: %v", err)
	}
	if _, err := Pull(bin, component, baseDir, testLogger()); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if result, err := Push(bin, component, baseDir, remote, testLogger()); err != nil {
		t.Errorf("Push: %v", err)
	} else if result.OutputPath != remote {
		t.Errorf("Push = %q, want the plugin to have been given --remote %q", result.OutputPath, remote)
	}
	if _, err := CheckPush(bin, component, baseDir, remote, testLogger()); err != nil {
		t.Errorf("CheckPush: %v", err)
	}
	if got, err := Remote(bin, component, baseDir, testLogger()); err != nil {
		t.Errorf("Remote: %v", err)
	} else if want := "remote-of-" + component.PackageURL; got != want {
		t.Errorf("Remote = %q, want %q", got, want)
	}
}
