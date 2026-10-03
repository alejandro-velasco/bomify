package security

import (
	"log/slog"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/testutil"
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
	} else if len(supported.Types) != 1 || supported.Types[0] != "oci" {
		t.Errorf("supportedComponents = %+v, want oci", supported)
	}
	if _, err := scanComponent(bin, cdx.Component{PackageURL: "pkg:oci/nginx@1.27"}, logger); err != nil {
		t.Errorf("scanComponent: %v", err)
	}
}
