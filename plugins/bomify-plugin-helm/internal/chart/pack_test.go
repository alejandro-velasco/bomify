package chart

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	helmchart "helm.sh/helm/v4/pkg/chart/v2"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"
	"helm.sh/helm/v4/pkg/registry"
)

// saveChart writes a chart of meta into dir as Pull stores one, returning
// the archive.
func saveChart(t *testing.T, dir string, meta *helmchart.Metadata) []byte {
	t.Helper()
	path, err := chartutil.Save(&helmchart.Chart{Metadata: meta}, dir)
	if err != nil {
		t.Fatalf("chartutil.Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testMetadata() *helmchart.Metadata {
	meta := &helmchart.Metadata{
		APIVersion:  helmchart.APIVersionV2,
		Name:        "mychart",
		Version:     "1.2.3+build.1",
		Description: "A test chart",
		Home:        "https://example.com/mychart",
		Sources:     []string{"https://github.com/example/mychart"},
		Maintainers: []*helmchart.Maintainer{{Name: "Ada", Email: "ada@example.com"}, {Name: "Bo"}},
	}
	return meta
}

var testRef = Ref{Name: "mychart", Version: "1.2.3+build.1"}

func TestPackBuildsTheChartAsHelmPushDoes(t *testing.T) {
	inputDir, outputDir := t.TempDir(), t.TempDir()
	archive := saveChart(t, inputDir, testMetadata())
	given := map[string]string{
		ocispec.AnnotationCreated: "2026-01-01T00:00:00Z",
		"land.bomify.purl":        "pkg:helm/mychart@1.2.3%2Bbuild.1",
	}

	result, err := Pack(inputDir, outputDir, testRef, given, testLogger())
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	for _, blob := range append(result.Blobs, *result.Manifest) {
		data, err := os.ReadFile(blob.Path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if "sha256:"+hex.EncodeToString(sum[:]) != blob.Digest || int64(len(data)) != blob.Size {
			t.Errorf("%s doesn't hold blob %s", blob.Path, blob.Digest)
		}
	}

	var manifest ocispec.Manifest
	manifestData, err := os.ReadFile(result.Manifest.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if result.Manifest.MediaType != ocispec.MediaTypeImageManifest || manifest.Config.MediaType != registry.ConfigMediaType || len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != registry.ChartLayerMediaType {
		t.Fatalf("manifest = %+v, want Helm's config and one chart layer", manifest)
	}

	// The layer is the stored archive as it is, the file Pull wrote.
	layer := result.Blobs[1]
	if layer.Path != filepath.Join(inputDir, testRef.Filename()) {
		t.Errorf("layer is at %s, want the stored archive", layer.Path)
	}
	if data, _ := os.ReadFile(layer.Path); !bytes.Equal(data, archive) {
		t.Error("layer isn't the archive as it is")
	}

	// Helm reads the config as the chart's metadata.
	configData, err := os.ReadFile(result.Blobs[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct{ APIVersion, Name, Version, Description string }
	if err := json.Unmarshal(configData, &config); err != nil || config.Name != "mychart" || config.Version != "1.2.3+build.1" || config.APIVersion != "v2" {
		t.Errorf("config = %s, %v; want the chart's metadata", configData, err)
	}

	want := map[string]string{
		ocispec.AnnotationTitle:       "mychart",
		ocispec.AnnotationVersion:     "1.2.3+build.1",
		ocispec.AnnotationDescription: "A test chart",
		ocispec.AnnotationURL:         "https://example.com/mychart",
		ocispec.AnnotationSource:      "https://github.com/example/mychart",
		ocispec.AnnotationAuthors:     "Ada (ada@example.com), Bo",
	}
	maps.Copy(want, given)
	if !maps.Equal(manifest.Annotations, want) {
		t.Errorf("annotations = %v, want %v", manifest.Annotations, want)
	}
}

func TestPackIsDeterministic(t *testing.T) {
	inputDir := t.TempDir()
	saveChart(t, inputDir, testMetadata())
	given := map[string]string{ocispec.AnnotationCreated: "2026-01-01T00:00:00Z"}

	var digests []string
	for range 2 {
		result, err := Pack(inputDir, t.TempDir(), testRef, given, testLogger())
		if err != nil {
			t.Fatalf("Pack: %v", err)
		}
		digests = append(digests, result.Manifest.Digest)
	}
	if digests[0] != digests[1] {
		t.Errorf("manifest digests %v differ between packs of the same chart", digests)
	}
}

func TestPackRefusesAChartThatIsntThePurls(t *testing.T) {
	inputDir := t.TempDir()
	other := testMetadata()
	other.Version = "9.9.9"
	archive := saveChart(t, t.TempDir(), other)
	if err := os.WriteFile(filepath.Join(inputDir, testRef.Filename()), archive, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Pack(inputDir, t.TempDir(), testRef, nil, testLogger())
	if err == nil || !strings.Contains(err.Error(), "holds chart mychart 9.9.9, not the purl's mychart 1.2.3+build.1") {
		t.Errorf("Pack = %v, want the chart refused as not the purl's", err)
	}
}

func TestPackRefusesWhatIsntAChart(t *testing.T) {
	inputDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(inputDir, testRef.Filename()), []byte("not a chart"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(inputDir, t.TempDir(), testRef, nil, testLogger()); err == nil {
		t.Error("Pack of a file that isn't a chart archive succeeded")
	}
}
