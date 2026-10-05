package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// generatedBOM is an SBOM the fake plugin prints back, rooted at a
// packaged pkg:generic/<name>@1.0 depending on each of components (purls).
func generatedBOM(name string, components ...string) string {
	root := fmt.Sprintf("pkg:generic/%s@1.0", name)
	list := []string{fmt.Sprintf(`{"type":"application","name":%q,"version":"1.0","purl":%q,"bom-ref":%q}`, name, root, root)}
	var on []string
	for _, purl := range components {
		list = append(list, fmt.Sprintf(`{"type":"container","name":"img","purl":%q,"bom-ref":%q}`, purl, purl))
		on = append(on, fmt.Sprintf("%q", purl))
	}
	return fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6",
		"metadata":{"component":{"type":"application","name":%q,"version":"1.0","purl":%q,"bom-ref":%q}},
		"components":[%s],"dependencies":[{"ref":%q,"dependsOn":[%s]}]}`,
		name, root, root, strings.Join(list, ","), root, strings.Join(on, ","))
}

// runCompose writes files into a fresh directory and runs "sbom compose
// bomify.yaml -o out.cdx.json" there with the fake plugin installed as
// bomify-plugin-fake, returning the directory and the error.
func runCompose(t *testing.T, files map[string]string) (string, error) {
	t.Helper()
	useDataDir(t, buildFakePluginBinary(t, "fake"))
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"sbom", "compose", filepath.Join(dir, "bomify.yaml"), "-o", filepath.Join(dir, "out.cdx.json")})
	return dir, root.Execute()
}

func TestSBOMCompose(t *testing.T) {
	t.Setenv("FAKESBOM_LOG", filepath.Join(t.TempDir(), "runs"))
	dir, err := runCompose(t, map[string]string{
		"bomify.yaml": fmt.Sprintf(`
name: app
version: "2.0"
sources:
  - name: web
    medium: fake
    options: {bom: %s}
  - name: tools
    sbom: tools.cdx.json
`, generatedBOM("web", "pkg:oci/web@1.0", "pkg:oci/redis@7.4")),
		"tools.cdx.json": generatedBOM("tools", "pkg:oci/redis@7.4"),
	})
	if err != nil {
		t.Fatalf("sbom compose: %v", err)
	}

	bom := new(cdx.BOM)
	data, _ := os.ReadFile(filepath.Join(dir, "out.cdx.json"))
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		t.Fatalf("decode output: %v\n%s", err, data)
	}
	if bom.Metadata.Component.Name != "app" {
		t.Errorf("root = %+v, want the composition", bom.Metadata.Component)
	}
	var got []string
	for _, c := range *bom.Components {
		got = append(got, c.BOMRef+" "+(*c.Properties)[len(*c.Properties)-1].Value)
	}
	want := []string{
		"pkg:generic/tools@1.0 tools", "pkg:generic/web@1.0 web",
		"pkg:oci/redis@7.4 tools,web", "pkg:oci/web@1.0 web",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("components (bom-ref sources):\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSBOMComposeRejectsBrokenSource(t *testing.T) {
	_, err := runCompose(t, map[string]string{
		"bomify.yaml": "name: app\nversion: '2.0'\nsources: [{name: tools, sbom: tools.cdx.json}]\n",
		// No metadata.component.
		"tools.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`,
	})
	if err == nil || !strings.Contains(err.Error(), `source "tools"`) || !strings.Contains(err.Error(), "metadata.component is missing") {
		t.Errorf("sbom compose = %v, want the source's contract violation", err)
	}
}

func TestSBOMComposeFindsEveryPluginFirst(t *testing.T) {
	runs := filepath.Join(t.TempDir(), "runs")
	t.Setenv("FAKESBOM_LOG", runs)

	_, err := runCompose(t, map[string]string{
		"bomify.yaml": fmt.Sprintf(`
name: app
version: "2.0"
sources:
  - {name: good, medium: fake, options: {bom: %s}}
  - {name: web, medium: nosuch, options: {}}
`, generatedBOM("good")),
	})
	if err == nil || !strings.Contains(err.Error(), `source "web"`) || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("sbom compose = %v, want the missing plugin named", err)
	}
	if _, statErr := os.Stat(runs); statErr == nil {
		t.Error("a plugin ran before every source's plugin was found")
	}
}

func TestSBOMComposeRejectsUnknownFields(t *testing.T) {
	_, err := runCompose(t, map[string]string{
		"bomify.yaml":    "name: app\nversion: '2.0'\nsources: [{name: tools, sbom: tools.cdx.json}]\n",
		"tools.cdx.json": strings.Replace(generatedBOM("tools"), `"bomFormat"`, `"colour":"red","bomFormat"`, 1),
	})
	if err == nil || !strings.Contains(err.Error(), `source "tools"`) || !strings.Contains(err.Error(), `unknown field "colour"`) {
		t.Errorf("sbom compose = %v, want the unknown field rejected", err)
	}
}
