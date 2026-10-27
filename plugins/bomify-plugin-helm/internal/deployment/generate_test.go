package deployment

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// description is a package of a chart, tagged, and an image of the same
// name, untagged, as a package pushed with --skip-component-repositories
// would have it.
var description = plugin.DeploymentPackage{
	Reference:  "registry.example.com/team/app:1.0",
	Repository: "registry.example.com/team/app",
	Digest:     "sha256:package",
	Components: []plugin.DeploymentComponent{
		{
			Name: "podinfo", Version: "6.7.1", Purl: "pkg:helm/podinfo@6.7.1", Digest: "sha256:chart",
			Reference: "registry.example.com/team/app@sha256:chart",
			Tagged: &plugin.TaggedReference{
				Registry: "registry.example.com", Repository: "team/app/helm/podinfo", Tag: "6.7.1",
				Reference: "registry.example.com/team/app/helm/podinfo:6.7.1",
			},
		},
		{
			Name: "podinfo", Version: "6.7.1", Purl: "pkg:oci/podinfo@6.7.1", Digest: "sha256:image",
			Reference: "registry.example.com/team/app@sha256:image",
		},
	},
}

// request is a generate request of the files templates writes, named
// config, then overlay-1, overlay-2, and so on, into a fresh directory.
func request(t *testing.T, options map[string]string, templates ...string) plugin.GenerateRequest {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for index, template := range templates {
		name := "config.tmpl"
		if index > 0 {
			name = "overlay-" + string(rune('0'+index)) + ".tmpl"
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(template), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	req := plugin.GenerateRequest{
		Name:    "web",
		Package: description,
		Output:  t.TempDir(),
		Options: options,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if len(paths) > 0 {
		req.Config = paths[0]
		req.Overlays = paths[1:]
	}
	return req
}

// values is what Generate wrote into req.Output.
func values(t *testing.T, req plugin.GenerateRequest) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(req.Output, ValuesFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestGenerate(t *testing.T) {
	config := `image:
  repository: {{ (component "oci/podinfo").reference }}
  digest: {{ (component "pkg:oci/podinfo@6.7.1").digest }}
package: {{ .Package.digest }}
labels:
{{ toYaml (dict "app" "web" "tier" "front") | indent 2 }}
`
	req := request(t, map[string]string{"chart": "podinfo"}, config)

	result, err := Generate(req)

	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := `image:
  digest: sha256:image
  repository: registry.example.com/team/app@sha256:image
labels:
  app: web
  tier: front
package: sha256:package
`
	if got := values(t, req); got != want {
		t.Errorf("values:\n%s\nwant:\n%s", got, want)
	}
	if strings.Join(result.Files, ",") != ValuesFile {
		t.Errorf("files = %q, want just %s", result.Files, ValuesFile)
	}
	wantInstructions := "helm upgrade --install web oci://registry.example.com/team/app/helm/podinfo@sha256:chart --values values.yaml"
	if result.Instructions != wantInstructions {
		t.Errorf("instructions = %q, want %q", result.Instructions, wantInstructions)
	}
}

func TestGenerateMergesOverlaysAsHelmValuesFiles(t *testing.T) {
	config := "image:\n  tag: \"1.0\"\n  pullPolicy: Always\nlist:\n  - a\n  - b\nkept: value\n"
	first := "image:\n  tag: \"2.0\"\nlist:\n  - c\n"
	second := "image:\n  pullPolicy: null\nadded: true\n"
	req := request(t, nil, config, first, second)

	if _, err := Generate(req); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	want := "added: true\nimage:\n  pullPolicy: null\n  tag: \"2.0\"\nkept: value\nlist:\n- c\n"
	if got := values(t, req); got != want {
		t.Errorf("values:\n%s\nwant:\n%s", got, want)
	}
}

func TestGenerateRefuses(t *testing.T) {
	for name, test := range map[string]struct {
		options  map[string]string
		template string
		want     string
	}{
		"a missing key":               {template: "tag: {{ (component \"oci/podinfo\").tagged.tag }}\n", want: "map has no entry for key \"tagged\""},
		"a name two components share": {template: "x: {{ (component \"podinfo\").digest }}\n", want: "names several components"},
		"an unknown component":        {template: "x: {{ (component \"nginx\").digest }}\n", want: "no component \"nginx\""},
		"an unknown option":           {options: map[string]string{"replicas": "3"}, want: "unknown option \"replicas\""},
		"a chart it lacks":            {options: map[string]string{"chart": "nginx"}, want: "option chart"},
		"values that aren't YAML":     {template: "{{ \"]\" }}\n", want: "didn't render YAML"},
	} {
		t.Run(name, func(t *testing.T) {
			var templates []string
			if test.template != "" {
				templates = append(templates, test.template)
			}
			req := request(t, test.options, templates...)

			_, err := Generate(req)

			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("Generate = %v, want an error containing %q", err, test.want)
			}
		})
	}
}

// TestGenerateChoosesAmongCharts covers a chart named like one of the
// package's images, which "chart" finds, and a package with one chart,
// which needs no "chart" at all.
func TestGenerateChoosesAmongCharts(t *testing.T) {
	for name, options := range map[string]map[string]string{
		"by a name an image shares": {"chart": "podinfo"},
		"the only chart":            nil,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := Generate(request(t, options))

			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if !strings.Contains(result.Instructions, "helm/podinfo@sha256:chart") {
				t.Errorf("instructions = %q, want the chart", result.Instructions)
			}
		})
	}
}

func TestGenerateNeedsAChartAmongSeveral(t *testing.T) {
	req := request(t, nil)
	second := plugin.DeploymentComponent{Name: "redis", Version: "1.0", Purl: "pkg:helm/redis@1.0", Digest: "sha256:redis", Reference: "registry.example.com/team/app@sha256:redis"}
	req.Package.Components = append(append([]plugin.DeploymentComponent{}, description.Components...), second)

	_, err := Generate(req)

	if err == nil || !strings.Contains(err.Error(), "several charts (podinfo, redis)") {
		t.Errorf("Generate = %v, want it to ask which chart", err)
	}
}

// TestGenerateInstallsAnUntaggedChartFromThePackage covers a package
// pushed without component repositories: the chart is installed from the
// package's repository, by digest.
func TestGenerateInstallsAnUntaggedChartFromThePackage(t *testing.T) {
	req := request(t, map[string]string{"release": "site"})
	untagged := description.Components[0]
	untagged.Tagged = nil
	req.Package.Components = []plugin.DeploymentComponent{untagged}

	result, err := Generate(req)

	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := "helm upgrade --install site oci://registry.example.com/team/app@sha256:chart --values values.yaml"
	if result.Instructions != want {
		t.Errorf("instructions = %q, want %q", result.Instructions, want)
	}
	if got := values(t, req); got != "{}\n" {
		t.Errorf("values = %q, want empty ones", got)
	}
}
