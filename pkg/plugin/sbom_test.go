package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/pflag"
)

const (
	rootPurl  = "pkg:helm/app@1.0"
	imagePurl = "pkg:oci/app@1.0"
)

// validBOM is a minimal SBOM following every output rule: a root that's
// also packaged, one more component, and a dependency between them.
func validBOM() *cdx.BOM {
	root := cdx.Component{Type: cdx.ComponentTypeApplication, Name: "app", Version: "1.0", PackageURL: rootPurl, BOMRef: rootPurl}
	image := cdx.Component{Type: cdx.ComponentTypeContainer, Name: "app", Version: "1.0", PackageURL: imagePurl, BOMRef: imagePurl}
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &root}
	bom.Components = &[]cdx.Component{root, image}
	bom.Dependencies = &[]cdx.Dependency{{Ref: rootPurl, Dependencies: &[]string{imagePurl}}}
	return bom
}

func TestValidateGeneratedAcceptsValid(t *testing.T) {
	if err := ValidateGenerated(validBOM()); err != nil {
		t.Errorf("ValidateGenerated = %v, want nil", err)
	}
}

func TestValidateGeneratedOlderSpecVersions(t *testing.T) {
	for _, v := range []cdx.SpecVersion{cdx.SpecVersion1_5, cdx.SpecVersion1_6} {
		bom := validBOM()
		bom.SpecVersion = v
		if err := ValidateGenerated(bom); err != nil {
			t.Errorf("CycloneDX %s: ValidateGenerated = %v, want nil", v, err)
		}
	}
}

func TestValidateGeneratedRules(t *testing.T) {
	for name, tt := range map[string]struct {
		breakIt func(*cdx.BOM)
		want    string
	}{
		"no root":             {func(b *cdx.BOM) { b.Metadata = nil }, "metadata.component is missing"},
		"root has no version": {func(b *cdx.BOM) { b.Metadata.Component.Version = "" }, "metadata.component has no version"},
		"root has no purl": {func(b *cdx.BOM) {
			b.Metadata.Component.PackageURL, b.Metadata.Component.BOMRef = "", ""
		}, "metadata.component has no purl"},
		"component has no purl": {func(b *cdx.BOM) {
			(*b.Components)[1].PackageURL, (*b.Components)[1].BOMRef = "", ""
		}, "components[1] () has no purl"},
		"unparseable purl": {func(b *cdx.BOM) {
			(*b.Components)[1].PackageURL, (*b.Components)[1].BOMRef = "oci/app", "oci/app"
		}, `purl "oci/app"`},
		"bom-ref isn't the purl": {func(b *cdx.BOM) { (*b.Components)[1].BOMRef = "image" }, "isn't its purl"},
		"duplicate bom-ref": {func(b *cdx.BOM) {
			*b.Components = append(*b.Components, (*b.Components)[1])
		}, "isn't unique"},
		"nested components": {func(b *cdx.BOM) {
			(*b.Components)[1].Components = &[]cdx.Component{{Type: cdx.ComponentTypeFile, Name: "x"}}
		}, "has nested components"},
		"older spec version": {func(b *cdx.BOM) { b.SpecVersion = cdx.SpecVersion1_4 }, "specVersion 1.4 is older than 1.5"},
		"other fields": {func(b *cdx.BOM) {
			b.Services = &[]cdx.Service{{Name: "api"}}
			b.Vulnerabilities = &[]cdx.Vulnerability{{ID: "CVE-1"}}
		}, "has services, vulnerabilities; only metadata, components, and dependencies are allowed"},
		"dangling ref": {func(b *cdx.BOM) {
			*b.Dependencies = append(*b.Dependencies, cdx.Dependency{Ref: "pkg:oci/gone@1"})
		}, `ref "pkg:oci/gone@1" names no bom-ref`},
		"dangling dependsOn": {func(b *cdx.BOM) {
			*(*b.Dependencies)[0].Dependencies = append(*(*b.Dependencies)[0].Dependencies, "pkg:oci/gone@1")
		}, `dependsOn "pkg:oci/gone@1"`},
		"serial number": {func(b *cdx.BOM) { b.SerialNumber = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" }, "serialNumber"},
		"timestamp":     {func(b *cdx.BOM) { b.Metadata.Timestamp = "2026-01-01T00:00:00Z" }, "metadata.timestamp is set"},
	} {
		t.Run(name, func(t *testing.T) {
			bom := validBOM()
			tt.breakIt(bom)
			err := ValidateGenerated(bom)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ValidateGenerated = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

// fakeSBOM records the options SBOMCommand hands it and returns bom.
type fakeSBOM struct {
	options json.RawMessage
	bom     *cdx.BOM
}

func (f *fakeSBOM) Generate(_ context.Context, options json.RawMessage, _ *slog.Logger) (*cdx.BOM, error) {
	f.options = options
	return f.bom, nil
}

// runSBOM executes the sbom command tree around p with args, from dir,
// returning its stdout.
func runSBOM(t *testing.T, p SBOMPlugin, help SBOMHelp, dir string, args ...string) (string, error) {
	t.Helper()
	t.Chdir(dir)
	root := NewRootCommand("fake", "fake", SBOMCommand(p, help))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"sbom"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestSBOMCommandGenerateFromConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "opts.yaml"), []byte("chart: app\nvalues: [a.yaml]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &fakeSBOM{bom: validBOM()}

	out, err := runSBOM(t, p, SBOMHelp{}, dir, "generate", "--config", "opts.yaml")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if string(p.options) != `{"chart":"app","values":["a.yaml"]}` {
		t.Errorf("options = %s, want the YAML config as JSON", p.options)
	}
	var bom cdx.BOM
	if err := json.Unmarshal([]byte(out), &bom); err != nil || bom.Metadata.Component.PackageURL != rootPurl {
		t.Errorf("stdout = %q (%v), want the SBOM", out, err)
	}
}

func TestSBOMCommandDefaultConfig(t *testing.T) {
	help := SBOMHelp{DefaultConfig: "default.yaml"}

	p := &fakeSBOM{bom: validBOM()}
	if _, err := runSBOM(t, p, help, t.TempDir(), "generate"); err != nil || string(p.options) != "{}" {
		t.Errorf("missing default config: options %s, err %v; want {} and no error", p.options, err)
	}

	if _, err := runSBOM(t, p, help, t.TempDir(), "generate", "--config", "default.yaml"); err == nil {
		t.Error("missing explicit --config: error = nil, want one")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "default.yaml"), []byte("chart: app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runSBOM(t, p, help, dir, "generate"); err != nil || string(p.options) != `{"chart":"app"}` {
		t.Errorf("present default config: options %s, err %v; want it read", p.options, err)
	}
}

func TestSBOMCommandFlagsApplyOverConfig(t *testing.T) {
	var chart string
	help := SBOMHelp{Flags: func(flags *pflag.FlagSet) func(json.RawMessage) (json.RawMessage, error) {
		flags.StringVar(&chart, "chart", "", "")
		return func(options json.RawMessage) (json.RawMessage, error) {
			m := map[string]any{}
			if err := json.Unmarshal(options, &m); err != nil {
				return nil, err
			}
			if flags.Changed("chart") {
				m["chart"] = chart
			}
			return json.Marshal(m)
		}
	}}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "opts.json"), []byte(`{"chart":"old","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &fakeSBOM{bom: validBOM()}

	if _, err := runSBOM(t, p, help, dir, "generate", "--config", "opts.json", "--chart", "new"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if string(p.options) != `{"chart":"new","version":"1"}` {
		t.Errorf("options = %s, want --chart over the config's chart", p.options)
	}
}

func TestSBOMCommandRefusesBrokenSBOM(t *testing.T) {
	bom := validBOM()
	bom.SerialNumber = "urn:uuid:1"

	out, err := runSBOM(t, &fakeSBOM{bom: bom}, SBOMHelp{}, t.TempDir(), "generate")
	if err == nil || !strings.Contains(err.Error(), "breaks the SBOM contract") {
		t.Errorf("generate = %v, want the contract violation", err)
	}
	if out != "" {
		t.Errorf("stdout = %q, want nothing printed", out)
	}
}

func TestSBOMCommandOutputFile(t *testing.T) {
	dir := t.TempDir()
	out, err := runSBOM(t, &fakeSBOM{bom: validBOM()}, SBOMHelp{}, dir, "generate", "-o", "sbom.json")
	if err != nil || out != "" {
		t.Fatalf("generate -o = %q, %v; want nothing on stdout", out, err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "sbom.json")); err != nil || !strings.Contains(string(data), rootPurl) {
		t.Errorf("sbom.json = %q, %v; want the SBOM", data, err)
	}
}

func TestDecodeOptionsRejectsUnknownKeys(t *testing.T) {
	var v struct {
		Chart string `json:"chart"`
	}
	if err := DecodeOptions(json.RawMessage(`{"chart":"a","chrat":"b"}`), &v); err == nil {
		t.Error("DecodeOptions = nil, want the unknown key rejected")
	}
}

func TestEncodeSBOMAtItsOwnVersion(t *testing.T) {
	bom := validBOM()
	bom.SpecVersion = cdx.SpecVersion1_5

	var out bytes.Buffer
	if err := EncodeSBOM(&out, bom); err != nil {
		t.Fatalf("EncodeSBOM: %v", err)
	}
	for _, want := range []string{`"specVersion": "1.5"`, `"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("EncodeSBOM wrote:\n%s\nwant it to contain %s", out.String(), want)
		}
	}
}
