package cmd

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/oci/push"
)

// TestLogPushedLayersNamesWhereEachWasPublished covers a layer's log line:
// it names the component repository its component was published at, and
// nothing for a component that wasn't.
func TestLogPushedLayersNamesWhereEachWasPublished(t *testing.T) {
	model := "pkg:huggingface/microsoft/Phi-4@abc"
	image := "pkg:oci/nginx@1.27"
	published := push.PublishedComponent{
		Purls:     []string{model},
		Reference: "registry.example.com/packages/app/huggingface/microsoft/phi-4:abc",
		Digest:    "sha256:0123",
	}
	result := push.Result{
		Layers: []push.PushedLayer{
			{Purl: model, Hash: "aaaa"},
			{Purl: model, Hash: "bbbb"},
			{Purl: image, Hash: "cccc"},
		},
		Components: []push.PublishedComponent{published},
	}

	var logs strings.Builder
	logPushedLayers(slog.New(slog.NewTextHandler(&logs, nil)), result)

	var layerLines []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, `msg="layer pushed"`) {
			layerLines = append(layerLines, line)
		}
	}
	if len(layerLines) != 3 {
		t.Fatalf("logged %d layer lines, want 3:\n%s", len(layerLines), logs.String())
	}
	for _, line := range layerLines[:2] {
		if !strings.Contains(line, "published="+published.Reference) {
			t.Errorf("model's layer line %q doesn't name %s", line, published.Reference)
		}
	}
	if strings.Contains(layerLines[2], "published=") {
		t.Errorf("unpublished image's layer line %q names a repository", layerLines[2])
	}
}
