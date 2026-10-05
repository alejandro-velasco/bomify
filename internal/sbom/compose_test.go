package sbom

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const (
	chartPurl    = "pkg:helm/web@1.0?repository_url=oci:%2F%2Fr"
	webImagePurl = "pkg:oci/web@1.0"
	sharedPurl   = "pkg:oci/redis@7.4"
)

func comp(purl, name string) cdx.Component {
	return cdx.Component{Type: cdx.ComponentTypeContainer, Name: name, Version: "1.0", PackageURL: purl, BOMRef: purl}
}

// part is an SBOM rooted at root, packaging root (when packaged) and
// components, with root depending on every component.
func part(source string, root cdx.Component, packaged bool, components ...cdx.Component) Part {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &root}
	all := slices.Clone(components)
	if packaged {
		all = append([]cdx.Component{root}, all...)
	}
	bom.Components = &all
	var on []string
	for _, c := range components {
		on = append(on, c.BOMRef)
	}
	bom.Dependencies = &[]cdx.Dependency{{Ref: root.BOMRef, Dependencies: &on}}
	return Part{Source: source, BOM: bom}
}

func composition() *Composition { return &Composition{Name: "app", Version: "2.0"} }

func TestMerge(t *testing.T) {
	web := part("web", comp(chartPurl, "web"), true, comp(webImagePurl, "web"), comp(sharedPurl, "redis"))
	db := part("db", comp("pkg:helm/db@1.0", "db"), true, comp(sharedPurl, "redis"))
	c := composition()
	c.Components = []cdx.Component{{Type: cdx.ComponentTypeFile, Name: "cli", PackageURL: "pkg:generic/cli@1.0"}}

	bom, err := c.Merge([]Part{web, db})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	root := bom.Metadata.Component
	if root.Name != "app" || root.Version != "2.0" || root.PackageURL != "pkg:generic/app@2.0" {
		t.Errorf("root = %+v, want the composition", root)
	}

	sources := map[string]string{}
	var order []string
	for _, c := range *bom.Components {
		order = append(order, c.BOMRef)
		for _, p := range *c.Properties {
			if p.Name == PropertySources {
				sources[c.BOMRef] = p.Value
			}
		}
	}
	if !slices.IsSorted(order) || len(order) != 5 {
		t.Errorf("components = %v, want 5, sorted by bom-ref, redis once", order)
	}
	for ref, want := range map[string]string{
		sharedPurl: "db,web", webImagePurl: "web", "pkg:generic/cli@1.0": "components",
	} {
		if sources[ref] != want {
			t.Errorf("%s sources = %q, want %q", ref, sources[ref], want)
		}
	}

	deps := map[string][]string{}
	for _, d := range *bom.Dependencies {
		deps[d.Ref] = *d.Dependencies
	}
	if want := []string{"pkg:generic/cli@1.0", "pkg:helm/db@1.0", chartPurl}; !slices.Equal(deps["pkg:generic/app@2.0"], want) {
		t.Errorf("app depends on %v, want %v", deps["pkg:generic/app@2.0"], want)
	}
	if want := []string{sharedPurl, webImagePurl}; !slices.Equal(deps[chartPurl], want) {
		t.Errorf("web chart depends on %v, want its own edges %v", deps[chartPurl], want)
	}
}

func TestMergeUnpackagedRoot(t *testing.T) {
	tools := part("tools", comp("pkg:generic/tools@1.0", "tools"), false, comp("pkg:generic/a@1.0", "a"), comp("pkg:generic/b@1.0", "b"))

	bom, err := composition().Merge([]Part{tools})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	for _, d := range *bom.Dependencies {
		if d.Ref == "pkg:generic/tools@1.0" {
			t.Errorf("dependencies keep the unpackaged root's edges: %+v", d)
		}
		if d.Ref == "pkg:generic/app@2.0" && !slices.Equal(*d.Dependencies, []string{"pkg:generic/a@1.0", "pkg:generic/b@1.0"}) {
			t.Errorf("app depends on %v, want the unpackaged root's components", *d.Dependencies)
		}
	}
}

func TestMergeConflict(t *testing.T) {
	other := comp(sharedPurl, "redis")
	other.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "abc"}}

	_, err := composition().Merge([]Part{
		part("web", comp(chartPurl, "web"), true, comp(sharedPurl, "redis")),
		part("db", comp("pkg:helm/db@1.0", "db"), true, other),
	})
	if err == nil || !strings.Contains(err.Error(), `sources "web" and "db" disagree on its hashes`) {
		t.Errorf("Merge = %v, want the hash conflict", err)
	}
}

func TestMergeRejectsBrokenPart(t *testing.T) {
	broken := part("web", comp(chartPurl, "web"), true)
	broken.BOM.SerialNumber = "urn:uuid:1"

	if _, err := composition().Merge([]Part{broken}); err == nil || !strings.Contains(err.Error(), `source "web"`) {
		t.Errorf("Merge = %v, want the source's contract violation", err)
	}
}

func TestMergeIsDeterministic(t *testing.T) {
	encode := func(components ...cdx.Component) []byte {
		bom, err := composition().Merge([]Part{part("web", comp(chartPurl, "web"), true, components...)})
		if err != nil {
			t.Fatalf("Merge: %v", err)
		}
		var buf bytes.Buffer
		if err := Write(&buf, bom); err != nil {
			t.Fatalf("Write: %v", err)
		}
		return buf.Bytes()
	}

	a := encode(comp(webImagePurl, "web"), comp(sharedPurl, "redis"))
	b := encode(comp(sharedPurl, "redis"), comp(webImagePurl, "web"))
	if !bytes.Equal(a, b) {
		t.Errorf("same components in another order composed differently:\n%s\n---\n%s", a, b)
	}
	if !bytes.Contains(a, []byte(`"specVersion": "1.6"`)) || bytes.Contains(a, []byte("serialNumber")) || bytes.Contains(a, []byte("timestamp")) {
		t.Errorf("composed SBOM isn't pinned to 1.6 without serial number or timestamp:\n%s", a)
	}
}

func writeComposition(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bomify.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadComposition(t *testing.T) {
	path := writeComposition(t, `
name: app
version: "2.0"
sources:
  - name: web
    medium: helm
    options: {chart: web}
  - name: tools
    sbom: vendor/tools.cdx.json
`)
	c, err := LoadComposition(path)
	if err != nil {
		t.Fatalf("LoadComposition: %v", err)
	}
	if c.Dir() != filepath.Dir(path) || c.Path("vendor/tools.cdx.json") != filepath.Join(filepath.Dir(path), "vendor", "tools.cdx.json") {
		t.Errorf("Dir = %q, Path = %q; want them relative to the file", c.Dir(), c.Path("vendor/tools.cdx.json"))
	}
	if string(c.Sources[0].OptionsJSON()) != `{"chart":"web"}` || string(c.Sources[1].OptionsJSON()) != "{}" {
		t.Errorf("options = %s, %s", c.Sources[0].OptionsJSON(), c.Sources[1].OptionsJSON())
	}
	if c.Sources[0].Type() != SourcePlugin || c.Sources[1].Type() != SourceSBOM {
		t.Errorf("types = %v, %v; want SourcePlugin, SourceSBOM", c.Sources[0].Type(), c.Sources[1].Type())
	}
}

func TestLoadCompositionRejects(t *testing.T) {
	for name, tt := range map[string]struct{ content, want string }{
		"unknown key":      {"name: a\nversion: '1'\nsorces: []\n", "unknown field"},
		"no name":          {"version: '1'\nsources: [{name: s, sbom: x.json}]\n", `"name" and "version"`},
		"nothing":          {"name: a\nversion: '1'\n", "nothing to compose"},
		"medium and sbom":  {"name: a\nversion: '1'\nsources: [{name: s, medium: helm, sbom: x.json}]\n", `exactly one of "medium" or "sbom"`},
		"neither":          {"name: a\nversion: '1'\nsources: [{name: s}]\n", `exactly one of "medium" or "sbom"`},
		"options for sbom": {"name: a\nversion: '1'\nsources: [{name: s, sbom: x.json, options: {}}]\n", `"options" only go with "medium"`},
		"duplicate name":   {"name: a\nversion: '1'\nsources: [{name: s, sbom: x.json}, {name: s, sbom: y.json}]\n", `name "s" is taken`},
		"reserved name":    {"name: a\nversion: '1'\nsources: [{name: components, sbom: x.json}]\n", `name "components" is taken`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadComposition(writeComposition(t, tt.content))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("LoadComposition = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}
