package plugin

import (
	"strings"
	"testing"
)

func TestMatchesSelector(t *testing.T) {
	const (
		image = "pkg:oci/podinfo@6.7.1?repository_url=ghcr.io/stefanprodan/podinfo"
		model = "pkg:huggingface/HuggingFaceTB/SmolLM2-135M@93efa2f"
	)
	for _, test := range []struct {
		purl, name, version, selector string
		want                          bool
	}{
		{image, "podinfo", "6.7.1", image, true},
		{image, "podinfo", "6.7.1", "podinfo", true},
		{image, "podinfo", "6.7.1", "podinfo@6.7.1", true},
		{image, "podinfo", "6.7.1", "oci/podinfo", true},
		{image, "podinfo", "6.7.1", "oci/podinfo@6.7.1", true},
		{image, "podinfo", "6.7.1", "pkg:oci/podinfo", true},
		{image, "podinfo", "6.7.1", "pkg:oci/podinfo@6.7.1", true},
		{image, "podinfo", "6.7.1", "helm/podinfo", false},
		{image, "podinfo", "6.7.1", "oci/podinfo@6.8.0", false},
		{image, "podinfo", "6.7.1", "podinfo@6.8.0", false},
		{model, "SmolLM2-135M", "93efa2f", "huggingface/HuggingFaceTB/SmolLM2-135M", true},
		{model, "SmolLM2-135M", "93efa2f", "huggingface/SmolLM2-135M", false},
		{model, "SmolLM2-135M", "93efa2f", "SmolLM2-135M", true},
		{"not a purl", "x", "1", "oci/x", false},
		{image, "podinfo", "6.7.1", "", false},
	} {
		if got := MatchesSelector(test.purl, test.name, test.version, test.selector); got != test.want {
			t.Errorf("MatchesSelector(%q, %q) = %v, want %v", test.purl, test.selector, got, test.want)
		}
	}
}

func TestSelectComponent(t *testing.T) {
	chart := DeploymentComponent{Name: "podinfo", Version: "6.7.1", Purl: "pkg:helm/podinfo@6.7.1"}
	image := DeploymentComponent{Name: "podinfo", Version: "6.7.1", Purl: "pkg:oci/podinfo@6.7.1?repository_url=ghcr.io/stefanprodan/podinfo"}
	mirrored := DeploymentComponent{Name: "podinfo", Version: "6.7.1", Purl: "pkg:oci/podinfo@6.7.1?repository_url=mirror.example.com/podinfo"}
	components := []DeploymentComponent{chart, image}

	for selector, want := range map[string]DeploymentComponent{
		"oci/podinfo":           image,
		"helm/podinfo@6.7.1":    chart,
		"pkg:oci/podinfo@6.7.1": image,
		image.Purl:              image,
	} {
		got, err := SelectComponent(components, selector)
		if err != nil || got.Purl != want.Purl {
			t.Errorf("SelectComponent(%q) = %v, %v, want %s", selector, got.Purl, err, want.Purl)
		}
	}

	_, err := SelectComponent(components, "podinfo@6.7.1")
	if err == nil || !strings.Contains(err.Error(), "names several components") || !strings.Contains(err.Error(), chart.Purl) {
		t.Errorf("SelectComponent(podinfo@6.7.1) = %v, want it to list both", err)
	}
	if _, err := SelectComponent(components, "nginx"); err == nil || !strings.Contains(err.Error(), `no component "nginx"`) {
		t.Errorf("SelectComponent(nginx) = %v, want none found", err)
	}
	// Two copies of an image differing only in qualifiers: the whole purl
	// tells them apart.
	got, err := SelectComponent([]DeploymentComponent{image, mirrored}, mirrored.Purl)
	if err != nil || got.Purl != mirrored.Purl {
		t.Errorf("SelectComponent(the mirrored purl) = %v, %v", got.Purl, err)
	}
}
