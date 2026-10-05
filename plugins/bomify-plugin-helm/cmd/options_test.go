package cmd

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

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

func TestAddExtraComponents(t *testing.T) {
	const chart, image = "pkg:helm/web@1.0", "pkg:oci/web@1.0"
	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{{Name: "web", PackageURL: chart, BOMRef: chart}, {Name: "web", PackageURL: image, BOMRef: image}}
	bom.Dependencies = &[]cdx.Dependency{{Ref: chart, Dependencies: &[]string{image}}}

	addExtraComponents(bom, []cdx.Component{
		{Name: "lib", PackageURL: "pkg:generic/lib@1.0"},
		{Name: "kept", PackageURL: "pkg:generic/kept@1.0", BOMRef: "pkg:generic/kept@1.0"},
	})

	got := *bom.Components
	if len(got) != 4 || got[2].BOMRef != "pkg:generic/lib@1.0" || got[3].BOMRef != "pkg:generic/kept@1.0" {
		t.Errorf("components = %+v, want the extras appended, each bom-ref its purl", got)
	}
	if on := *(*bom.Dependencies)[0].Dependencies; !slices.Equal(on, []string{image, "pkg:generic/lib@1.0", "pkg:generic/kept@1.0"}) {
		t.Errorf("chart depends on %v, want its image and the extras", on)
	}
}
