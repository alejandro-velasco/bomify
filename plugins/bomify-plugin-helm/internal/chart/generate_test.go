package chart

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	helmchart "helm.sh/helm/v3/pkg/chart"
)

func TestImageComponentTag(t *testing.T) {
	c, err := imageComponent("docker.io/bitnami/postgresql:18.11.6")
	if err != nil {
		t.Fatalf("imageComponent() error = %v", err)
	}

	if c.Name != "postgresql" {
		t.Errorf("Name = %q, want %q", c.Name, "postgresql")
	}
	if c.Version != "18.11.6" {
		t.Errorf("Version = %q, want %q", c.Version, "18.11.6")
	}
	wantPurl := "pkg:oci/postgresql@18.11.6?repository_url=index.docker.io%2Fbitnami%2Fpostgresql"
	if c.PackageURL != wantPurl {
		t.Errorf("PackageURL = %q, want %q", c.PackageURL, wantPurl)
	}
	if c.BOMRef != wantPurl {
		t.Errorf("BOMRef = %q, want %q (the same purl)", c.BOMRef, wantPurl)
	}
}

func TestImageComponentDigest(t *testing.T) {
	digest := "sha256:9d5aec50e4ace532e44f5459f1f4d9c17180c96318103a6f64b765864967d310"
	c, err := imageComponent("registry.example.com/team/app@" + digest)
	if err != nil {
		t.Fatalf("imageComponent() error = %v", err)
	}

	if c.Name != "app" {
		t.Errorf("Name = %q, want %q", c.Name, "app")
	}
	if c.Version != digest {
		t.Errorf("Version = %q, want %q", c.Version, digest)
	}
	if c.BOMRef != c.PackageURL {
		t.Errorf("BOMRef = %q, want it to equal PackageURL %q", c.BOMRef, c.PackageURL)
	}
}

func TestImageComponentInvalidReference(t *testing.T) {
	if _, err := imageComponent("not a valid image ref!!"); err == nil {
		t.Fatal("imageComponent() error = nil, want error for an invalid reference")
	}
}

func TestChartVersion(t *testing.T) {
	if got := chartVersion(&helmchart.Chart{Metadata: &helmchart.Metadata{Version: "1.2.3"}}); got != "1.2.3" {
		t.Errorf("chartVersion() = %q, want %q", got, "1.2.3")
	}
	if got := chartVersion(&helmchart.Chart{}); got != "" {
		t.Errorf("chartVersion() with nil Metadata = %q, want empty", got)
	}
}

func TestBuildBOMIncludesChartMetadataAndComponents(t *testing.T) {
	chrt := &helmchart.Chart{Metadata: &helmchart.Metadata{Name: "postgresql", Version: "18.11.6"}}
	images := []imageRef{
		{Reference: "docker.io/bitnami/postgresql:18.11.6", Source: "StatefulSet/postgresql"},
	}

	bom, err := buildBOM(chrt, "oci://registry-1.docker.io/bitnamicharts", images)
	if err != nil {
		t.Fatalf("buildBOM() error = %v", err)
	}

	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("buildBOM() BOM has no metadata component")
	}
	if bom.Metadata.Component.Name != "postgresql" || bom.Metadata.Component.Version != "18.11.6" {
		t.Errorf("metadata component = %+v, want name=postgresql version=18.11.6", bom.Metadata.Component)
	}
	wantChartPurl := "pkg:helm/postgresql@18.11.6?repository_url=oci:%2F%2Fregistry-1.docker.io%2Fbitnamicharts"
	if bom.Metadata.Component.PackageURL != wantChartPurl {
		t.Errorf("metadata component PackageURL = %q, want %q", bom.Metadata.Component.PackageURL, wantChartPurl)
	}

	// The chart itself must be the first entry in Components — not just
	// Metadata.Component — since "bomify build" only ever walks
	// Components, never Metadata.Component; the image comes second.
	if bom.Components == nil || len(*bom.Components) != 2 {
		t.Fatalf("buildBOM() Components = %v, want 2 entries (chart + image)", bom.Components)
	}
	chartComponent, imageComp := (*bom.Components)[0], (*bom.Components)[1]
	if chartComponent.Type != cdx.ComponentTypeApplication || chartComponent.PackageURL != wantChartPurl || chartComponent.BOMRef != wantChartPurl {
		t.Errorf("components[0] = %+v, want the chart component (type=application, purl=bom-ref=%q)", chartComponent, wantChartPurl)
	}
	if imageComp.Type != cdx.ComponentTypeContainer || imageComp.Name != "postgresql" || imageComp.BOMRef != imageComp.PackageURL {
		t.Errorf("components[1] = %+v, want the discovered image component with BOMRef == PackageURL", imageComp)
	}
}

func TestGenerateInvalidKubeVersionErrorsBeforeNetworkAccess(t *testing.T) {
	// A bogus --kube-version must be rejected up front, before Generate
	// ever tries to resolve/fetch the chart — this repository URL isn't
	// reachable, so a timeout (rather than an immediate parse error)
	// would mean that ordering regressed.
	_, err := Generate(GenerateOptions{
		Name:          "postgresql",
		RepositoryURL: "https://chart-repo.invalid",
		KubeVersion:   "not-a-version",
	}, testLogger())
	if err == nil {
		t.Fatal("Generate() error = nil, want an error for an invalid --kube-version")
	}
}

func TestChartPurlRoundTripsThroughResolve(t *testing.T) {
	for _, repositoryURL := range []string{
		"oci://registry-1.docker.io/bitnamicharts",
		"https://charts.example.com/stable",
	} {
		purl := chartPurl("postgresql", "18.11.6", repositoryURL)

		ref, err := Resolve(purl)
		if err != nil {
			t.Fatalf("Resolve(chartPurl(...)) for %q error = %v", repositoryURL, err)
		}
		if ref.Name != "postgresql" || ref.Version != "18.11.6" || ref.RepositoryURL != repositoryURL {
			t.Errorf("Resolve(chartPurl(...)) for %q = %+v, want Name=postgresql Version=18.11.6 RepositoryURL=%q", repositoryURL, ref, repositoryURL)
		}
	}
}

func TestBuildBOMPropagatesImageComponentError(t *testing.T) {
	chrt := &helmchart.Chart{Metadata: &helmchart.Metadata{Name: "broken"}}
	images := []imageRef{{Reference: "not a valid image ref!!", Source: "Pod/broken"}}

	if _, err := buildBOM(chrt, "oci://registry.example.com/charts", images); err == nil {
		t.Fatal("buildBOM() error = nil, want error for an unparseable image reference")
	}
}
