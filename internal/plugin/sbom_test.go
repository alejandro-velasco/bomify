package plugin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/testutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// TestSBOMCallsParseWithPkgPlugin makes every SBOM generation call bomify
// makes against a plugin built with pkg/plugin's SBOMCommand (see
// TestCallsParseWithPkgPlugin).
func TestSBOMCallsParseWithPkgPlugin(t *testing.T) {
	dir := t.TempDir()
	testutil.InstallLibPlugin(t, dir, "lib")

	bin, err := Find(dir, "lib", pluginlib.SBOMContract)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	schema, err := SBOMSchema(bin)
	if err != nil {
		t.Fatalf("SBOMSchema: %v", err)
	}
	options := []byte(`{"name":"tool"}`)
	if err := ValidateOptions(schema, options); err != nil {
		t.Errorf("ValidateOptions(%s): %v", options, err)
	}

	config := writeOptions(t, string(options))
	bom, err := GenerateSBOM(bin, config, t.TempDir(), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	if got := bom.Metadata.Component.PackageURL; got != "pkg:generic/tool@1.0" {
		t.Errorf("root purl = %q, want the plugin's", got)
	}
}

func TestValidateOptions(t *testing.T) {
	schema := []byte(`{"type":"object","additionalProperties":false,"required":["chart"],"properties":{"chart":{"type":"string"}}}`)
	if err := ValidateOptions(schema, []byte(`{"chart":"web"}`)); err != nil {
		t.Errorf("valid options: %v", err)
	}
	for _, bad := range []string{`{}`, `{"chart":1}`, `{"chart":"web","chrat":"x"}`} {
		if err := ValidateOptions(schema, []byte(bad)); err == nil {
			t.Errorf("ValidateOptions(%s) = nil, want an error", bad)
		}
	}
	err := ValidateOptions(schema, []byte(`{"chart":"web","chrat":"x"}`))
	if err == nil || err.Error() != "at '': additional properties 'chrat' not allowed" {
		t.Errorf("ValidateOptions = %v, want just the violation", err)
	}
	if err := ValidateOptions([]byte(`not json`), []byte(`{}`)); err == nil {
		t.Error("an unparseable schema: error = nil, want one")
	}
}

func TestGenerateSBOMRunsInDirAndForwardsLogs(t *testing.T) {
	bin := testutil.InstallFakePlugin(t, t.TempDir(), "fake")
	runLog := filepath.Join(t.TempDir(), "runs")
	t.Setenv("FAKESBOM_LOG", runLog)
	dir := t.TempDir()

	var logs bytes.Buffer
	config := writeOptions(t, `{"bom":{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"a","version":"1","purl":"pkg:generic/a@1","bom-ref":"pkg:generic/a@1"}}}}`)
	if _, err := GenerateSBOM(bin, config, dir, &logs); err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}

	ran, _ := os.ReadFile(runLog)
	if got, want := strings.TrimSpace(string(ran)), dir; !sameDir(t, got, want) {
		t.Errorf("plugin ran in %q, want %q", got, want)
	}
	if !strings.Contains(logs.String(), "generating") {
		t.Errorf("logs = %q, want the plugin's stderr", logs.String())
	}
}

func TestGenerateSBOMRejectsBrokenSBOM(t *testing.T) {
	bin := testutil.InstallFakePlugin(t, t.TempDir(), "fake")
	config := writeOptions(t, `{"bom":{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1","metadata":{"component":{"name":"a","version":"1","purl":"pkg:generic/a@1","bom-ref":"pkg:generic/a@1"}}}}`)

	_, err := GenerateSBOM(bin, config, t.TempDir(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "breaks the SBOM contract") || !strings.Contains(err.Error(), "serialNumber") {
		t.Errorf("GenerateSBOM = %v, want the contract violation", err)
	}
}

func writeOptions(t *testing.T, options string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "options.json")
	if err := os.WriteFile(path, []byte(options), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// sameDir reports whether a and b are the same directory, however each
// is spelled (e.g. a short Windows path, or a symlinked temp dir).
func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ai, aerr := os.Stat(a)
	bi, berr := os.Stat(b)
	return aerr == nil && berr == nil && os.SameFile(ai, bi)
}
