package push

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

const chartYAML = `apiVersion: v2
name: mychart
version: 1.2.3+build.1
description: A test chart
`

// chartArchiveOf returns a chart archive, as `helm package` writes one,
// of files, each named under the chart's directory, mychart/.
func chartArchiveOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	for name, content := range files {
		header := &tar.Header{
			Name: "mychart/" + name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

var chartComponent = cdx.Component{
	Type:       cdx.ComponentTypeApplication,
	Name:       "mychart",
	Version:    "1.2.3+build.1",
	PackageURL: "pkg:helm/mychart@1.2.3%2Bbuild.1?repository_url=https://charts.example.com",
}

// writeChart writes archive into chartComponent's directory under
// baseDir, as bomify-plugin-helm stores a chart.
func writeChart(t *testing.T, baseDir string, archive []byte) {
	t.Helper()
	dir := layout.ComponentLayer(baseDir, chartComponent.PackageURL)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mychart-1.2.3+build.1.tgz"), archive, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPushPublishesAChartAsHelmDoes(t *testing.T) {
	archive := chartArchiveOf(t, map[string]string{"Chart.yaml": chartYAML, "templates/app.yaml": "kind: ConfigMap"})
	var digests []string
	for range 2 {
		reg := newRegistry(t)
		result, err := pushBuilt(t, reg, transfer.Options{}, []cdx.Component{chartComponent}, func(baseDir string) { writeChart(t, baseDir, archive) })
		if err != nil {
			t.Fatalf("Push: %v", err)
		}
		want := "registry.example.com/packages/app/helm/mychart:1.2.3_build.1"
		if len(result.Components) != 1 || result.Components[0].Reference != want {
			t.Fatalf("Components = %+v, want %s", result.Components, want)
		}
		digests = append(digests, result.Components[0].Digest)

		store := reg.store("registry.example.com/packages/app/helm/mychart")
		var manifest ocispec.Manifest
		fetchJSON(t, store, "1.2.3_build.1", &manifest)
		if manifest.Config.MediaType != helmConfigMediaType || len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != helmChartMediaType {
			t.Fatalf("manifest = %+v, want Helm's config and one chart layer", manifest)
		}
		if manifest.Annotations[ocispec.AnnotationTitle] != "mychart" || manifest.Annotations[ocispec.AnnotationVersion] != "1.2.3+build.1" {
			t.Errorf("annotations = %v, want the chart's name and version", manifest.Annotations)
		}
		layer, err := content.FetchAll(context.Background(), store, manifest.Layers[0])
		if err != nil || !bytes.Equal(layer, archive) {
			t.Errorf("chart layer = %d bytes, %v; want the archive as it is", len(layer), err)
		}
		// Helm reads the config as the chart's metadata.
		configData, err := content.FetchAll(context.Background(), store, manifest.Config)
		if err != nil {
			t.Fatal(err)
		}
		var config struct{ APIVersion, Name, Version, Description string }
		if err := json.Unmarshal(configData, &config); err != nil || config.Name != "mychart" || config.Version != "1.2.3+build.1" || config.APIVersion != "v2" {
			t.Errorf("config = %s, %v; want Chart.yaml as JSON", configData, err)
		}
	}
	if digests[0] != digests[1] {
		t.Errorf("digests %v differ between identical pushes", digests)
	}
}

func TestPushRefusesAChartWithoutChartYAML(t *testing.T) {
	archive := chartArchiveOf(t, map[string]string{"values.yaml": "a: 1"})
	reg := newRegistry(t)
	_, err := pushBuilt(t, reg, transfer.Options{}, []cdx.Component{chartComponent}, func(baseDir string) { writeChart(t, baseDir, archive) })
	if err == nil || !strings.Contains(err.Error(), "no Chart.yaml") {
		t.Fatalf("Push error = %v, want no Chart.yaml", err)
	}
	if _, err := reg.store("registry.example.com/packages/app").Resolve(context.Background(), packageRef); err == nil {
		t.Error("the package was tagged though its chart couldn't be published")
	}
}
