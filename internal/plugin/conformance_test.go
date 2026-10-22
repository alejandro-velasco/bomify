package plugin

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/layout"
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

	if _, err := Find(dir, "lib", pluginlib.ComponentContract); err != nil {
		t.Errorf("Find: %v", err)
	}
	if _, err := CheckPull(bin, component, baseDir, testLogger()); err != nil {
		t.Errorf("CheckPull: %v", err)
	}
	// With a tracker, as build pulls, so --progress is passed too.
	if _, err := Pull(bin, component, baseDir, testLogger(), &recordingTracker{}); err != nil {
		t.Errorf("Pull: %v", err)
	}
	input := layout.ComponentLayer(baseDir, component.PackageURL)
	packed, err := Pack(bin, component, baseDir, input, testLogger())
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var manifest struct {
		Annotations map[string]string `json:"annotations"`
	}
	if packed.Manifest == nil || json.Unmarshal(packed.Manifest.Data, &manifest) != nil || manifest.Annotations["input"] != input {
		t.Errorf("Pack = %+v, want the plugin to have been given --input %s", packed, input)
	}
}
