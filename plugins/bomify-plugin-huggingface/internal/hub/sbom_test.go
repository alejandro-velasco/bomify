package hub

import (
	"context"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

func TestGenerate(t *testing.T) {
	files := testFiles()
	files["README.md"] = "# model"
	fake := startFakeHub(t, &fakeHub{
		Files: files,
		LFS:   map[string]bool{"model.safetensors": true, "onnx/model.onnx": true},
		Info: map[string]any{
			"author":       "org",
			"pipeline_tag": "text-generation",
			"config":       map[string]any{"model_type": "gpt2", "architectures": []string{"GPT2LMHeadModel"}},
			"cardData": map[string]any{
				"license":    "apache-2.0",
				"datasets":   []string{"wikitext"},
				"base_model": "org/base",
			},
		},
	})
	options := GenerateOptions{
		RepoID:   "org/model",
		Revision: "main",
	}

	bom, err := Generate(context.Background(), fake.client(""), options, discardLogger())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := plugin.ValidateGenerated(bom); err != nil {
		t.Fatalf("ValidateGenerated: %v", err)
	}

	component := (*bom.Components)[0]
	if want := "pkg:huggingface/org/model@" + testCommit; component.PackageURL != want || component.BOMRef != want || bom.Metadata.Component.BOMRef != want {
		t.Errorf("purl = %q, bom-refs = %q, %q; want all %q, pinned to the commit", component.PackageURL, component.BOMRef, bom.Metadata.Component.BOMRef, want)
	}
	if component.Type != cdx.ComponentTypeMachineLearningModel {
		t.Errorf("type = %q", component.Type)
	}

	// The hash is the one a pull computes from the same files on disk,
	// without the weights ever being downloaded.
	dir := t.TempDir()
	writeFiles(t, dir, files)
	want, _, err := TreeHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := (*component.Hashes)[0].Value; got != want {
		t.Errorf("hash = %s, want a pull's, %s", got, want)
	}
	if len(fake.CDNAuthorization) != 0 {
		t.Errorf("downloaded %d LFS files, want none", len(fake.CDNAuthorization))
	}

	parameters := component.ModelCard.ModelParameters
	if parameters.Task != "text-generation" || parameters.ArchitectureFamily != "gpt2" || parameters.ModelArchitecture != "GPT2LMHeadModel" {
		t.Errorf("model parameters = %+v", parameters)
	}
	if datasets := *parameters.Datasets; len(datasets) != 1 || datasets[0].ComponentData.Name != "wikitext" || !strings.HasSuffix(datasets[0].ComponentData.Contents.URL, "/datasets/wikitext") {
		t.Errorf("datasets = %+v, want wikitext as data", datasets)
	}
	if licenses := *component.Licenses; len(licenses) != 1 || licenses[0].License.Name != "apache-2.0" {
		t.Errorf("licenses = %+v", licenses)
	}
	if component.Supplier == nil || component.Supplier.Name != "org" {
		t.Errorf("supplier = %+v", component.Supplier)
	}
	if properties := *component.Properties; len(properties) != 1 || properties[0].Value != "org/base" {
		t.Errorf("properties = %+v, want the base model", properties)
	}
}

func TestGenerateRecordsRepositoryURL(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{Files: testFiles()})
	options := GenerateOptions{
		RepoID:        "org/model",
		RepositoryURL: "https://hub.example.com",
	}

	bom, err := Generate(context.Background(), fake.client(""), options, discardLogger())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	purl := (*bom.Components)[0].PackageURL
	ref, err := Resolve(purl)
	if err != nil || ref.Endpoint != "https://hub.example.com" {
		t.Errorf("purl %q resolves to %+v, %v; want the hub as repository_url", purl, ref, err)
	}
	if (*bom.Components)[0].ModelCard != nil {
		t.Errorf("model card = %+v, want none when the Hub says nothing", (*bom.Components)[0].ModelCard)
	}
}

func TestGenerateRejects(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{Files: testFiles()})
	for _, tc := range []struct {
		options GenerateOptions
		want    string
	}{
		{GenerateOptions{RepoID: "model"}, "isn't <namespace>/<name>"},
		{GenerateOptions{RepoID: "org/model", Revision: "no-such-branch"}, "Invalid rev id"},
	} {
		if _, err := Generate(context.Background(), fake.client(""), tc.options, discardLogger()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Generate(%+v) = %v, want an error containing %q", tc.options, err, tc.want)
		}
	}
}

func TestStringList(t *testing.T) {
	for input, want := range map[string]int{`"mit"`: 1, `["mit", "apache-2.0"]`: 2, `""`: 0, `null`: 0} {
		var list stringList
		if err := list.UnmarshalJSON([]byte(input)); err != nil || len(list) != want {
			t.Errorf("stringList(%s) = %v, %v; want %d entries", input, list, err, want)
		}
	}
}
