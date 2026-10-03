package security

import (
	"log/slog"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/testutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// TestCallsParseWithPkgPlugin makes every security scanning contract call
// bomify makes against a plugin built with pkg/plugin's builders (see
// testutil.InstallLibPlugin), so an argument they don't accept fails here
// rather than in a real plugin.
func TestCallsParseWithPkgPlugin(t *testing.T) {
	bin := testutil.InstallLibPlugin(t, t.TempDir(), "lib")
	logger := slog.New(slog.DiscardHandler)

	if supported, err := supportedComponents(bin, logger); err != nil {
		t.Errorf("supportedComponents: %v", err)
	} else if len(supported.Types) != 2 || supported.Types["oci"] != pluginlib.ScanByPurl || supported.Types["generic"] != pluginlib.ScanByFiles {
		t.Errorf("supportedComponents = %+v, want oci by purl and generic by files", supported)
	}
	if _, err := scanComponent(bin, cdx.Component{PackageURL: "pkg:oci/nginx@1.27"}, "", logger); err != nil {
		t.Errorf("scanComponent: %v", err)
	}
	// With --input, pkg/plugin hands the files to the plugin's ScanInput.
	input := t.TempDir()
	if result, err := scanComponent(bin, cdx.Component{PackageURL: "pkg:generic/tool@1.0"}, input, logger); err != nil {
		t.Errorf("scanComponent with --input: %v", err)
	} else if result.Unscanned != "nothing to analyze in "+input {
		t.Errorf("scanComponent with --input = %+v, want the plugin's ScanInput to have been given %s", result, input)
	}
}
