package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/pflag"
)

// applyFlags parses args with generateFlags and applies them over config.
func applyFlags(t *testing.T, config string, args ...string) options {
	t.Helper()
	flags := pflag.NewFlagSet("generate", pflag.ContinueOnError)
	flags.String("config", "", "")
	apply := generateFlags(flags)
	if err := flags.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	raw, err := apply(json.RawMessage(config))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var o options
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatalf("decode applied options %s: %v", raw, err)
	}
	return o
}

func TestGenerateFlagsApplyOverConfig(t *testing.T) {
	config := `{"chart":"postgresql","repo":"oci://r/charts","version":"1.0","values":["a.yaml","b.yaml"],"namespace":"prod"}`

	o := applyFlags(t, config, "--version", "2.0", "-f", "c.yaml")

	want := options{Chart: "postgresql", Repo: "oci://r/charts", Version: "2.0", Values: []string{"c.yaml"}, Namespace: "prod"}
	if !reflect.DeepEqual(o, want) {
		t.Errorf("options = %+v, want %+v (flags over config, --values replacing)", o, want)
	}
}

func TestGenerateFlagsWithoutConfig(t *testing.T) {
	o := applyFlags(t, "{}", "--chart", "web", "--repo", "https://charts.example.com")

	// Unset flags leave their keys empty, for Generate's own defaults.
	if want := (options{Chart: "web", Repo: "https://charts.example.com"}); !reflect.DeepEqual(o, want) {
		t.Errorf("options = %+v, want %+v", o, want)
	}
}

func TestGenerateFlagsRejectUnknownKey(t *testing.T) {
	flags := pflag.NewFlagSet("generate", pflag.ContinueOnError)
	apply := generateFlags(flags)
	if _, err := apply(json.RawMessage(`{"chrat":"web"}`)); err == nil {
		t.Error("apply = nil error, want the unknown key rejected")
	}
}

func TestManifestFlagStillNamesConfig(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"sbom", "generate", "--manifest", "missing.yaml"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "read options") {
		t.Errorf("generate --manifest missing.yaml = %v, want it read as an explicit --config", err)
	}
}

func TestOptionsSchemaMatchesOptions(t *testing.T) {
	var schema struct {
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(optionsSchema, &schema); err != nil {
		t.Fatalf("options.schema.json: %v", err)
	}
	if schema.AdditionalProperties {
		t.Error("options.schema.json allows unknown keys")
	}

	var keys []string
	typ := reflect.TypeFor[options]()
	for i := range typ.NumField() {
		keys = append(keys, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
	}
	var props []string
	for key := range schema.Properties {
		props = append(props, key)
	}
	slices.Sort(keys)
	slices.Sort(props)
	if !slices.Equal(keys, props) {
		t.Errorf("schema properties %v, want options' keys %v", props, keys)
	}
}

func TestSchemaCommandPrintsSchema(t *testing.T) {
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"sbom", "schema"})
	if err := root.Execute(); err != nil || !bytes.Equal(out.Bytes(), optionsSchema) {
		t.Errorf("sbom schema = %q, %v; want options.schema.json", out.String(), err)
	}
}

func TestGenerateRequiresChartAndRepo(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for config, want := range map[string]string{
		`{}`:              `"chart"`,
		`{"chart":"web"}`: `"repo"`,
	} {
		if _, err := (sbomGenerator{}).Generate(context.Background(), json.RawMessage(config), logger); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Generate(%s) = %v, want an error naming %s", config, err, want)
		}
	}
}

func TestWithBOMRefs(t *testing.T) {
	got := withBOMRefs([]cdx.Component{
		{Name: "lib", PackageURL: "pkg:generic/lib@1.0"},
		{Name: "kept", PackageURL: "pkg:generic/kept@1.0", BOMRef: "pkg:generic/kept@1.0"},
	})
	if got[0].BOMRef != "pkg:generic/lib@1.0" || got[1].BOMRef != "pkg:generic/kept@1.0" {
		t.Errorf("withBOMRefs = %+v, want each bom-ref its purl", got)
	}
}
