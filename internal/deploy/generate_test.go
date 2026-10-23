package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"

	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/testutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

const ref = "registry.example.com/team/app:1.0"

// listed is a component of a package, as pull lists it, with a manifest
// whose digest comes from its purl and the tag reference given.
func listed(name, purl, reference string) pull.PackageComponent {
	component := pull.PackageComponent{
		Component: cdx.Component{Name: name, Version: "1.0", PackageURL: purl},
		Reference: reference,
		Manifest:  ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString(purl), ArtifactType: "application/vnd.test"},
	}
	return component
}

// resolver resolves the tags in tags, and finds no other.
func resolver(tags map[string]digest.Digest) TagResolver {
	return func(_ context.Context, reference string) (digest.Digest, error) {
		resolved, ok := tags[reference]
		if !ok {
			return "", fmt.Errorf("%s: %w", reference, errdef.ErrNotFound)
		}
		return resolved, nil
	}
}

func TestDescribe(t *testing.T) {
	chart := listed("chart-a", "pkg:helm/chart-a@1.0", "registry.example.com/team/app/helm/chart-a:1.0")
	moved := listed("image-a", "pkg:oci/image-a@1.0", "registry.example.com/team/app/oci/image-a:1.0")
	untagged := listed("image-b", "pkg:oci/image-b@1.0", "registry.example.com/team/app/oci/image-b@"+digest.FromString("pkg:oci/image-b@1.0").String())
	gone := listed("image-c", "pkg:oci/image-c@1.0", "registry.example.com/team/app/oci/image-c:1.0")
	tags := map[string]digest.Digest{
		chart.Reference: chart.Manifest.Digest,
		moved.Reference: digest.FromString("something else"),
	}

	description, err := Describe(context.Background(), ref, "sha256:package", []pull.PackageComponent{chart, moved, untagged, gone}, resolver(tags))

	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if description.Repository != "registry.example.com/team/app" || description.Digest != "sha256:package" || description.Reference != ref {
		t.Errorf("package = %+v", description)
	}
	got := description.Components
	if len(got) != 4 {
		t.Fatalf("components = %+v, want 4", got)
	}
	if got[0].Reference != "registry.example.com/team/app@"+chart.Manifest.Digest.String() || got[0].ArtifactType != "application/vnd.test" {
		t.Errorf("chart = %+v, want it pinned in the package's repository", got[0])
	}
	want := pluginlib.TaggedReference{Registry: "registry.example.com", Repository: "team/app/helm/chart-a", Tag: "1.0", Reference: chart.Reference}
	if got[0].Tagged == nil || *got[0].Tagged != want {
		t.Errorf("chart tagged = %+v, want %+v", got[0].Tagged, want)
	}
	for index, why := range map[int]string{1: "a tag pointing elsewhere", 2: "pinned by digest", 3: "a missing tag"} {
		if got[index].Tagged != nil {
			t.Errorf("%s: tagged = %+v, want none", why, got[index].Tagged)
		}
	}
}

func TestDescribeFailsWhenItCantCheckATag(t *testing.T) {
	chart := listed("chart-a", "pkg:helm/chart-a@1.0", "registry.example.com/team/app/helm/chart-a:1.0")
	unreachable := func(context.Context, string) (digest.Digest, error) { return "", fmt.Errorf("connection refused") }

	_, err := Describe(context.Background(), ref, "sha256:package", []pull.PackageComponent{chart}, unreachable)

	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("Describe = %v, want the registry's error", err)
	}
}

// generateWith runs Generate for file into a fresh output, with the fake
// plugin installed as bomify-plugin-fakedeploy.
func generateWith(t *testing.T, file File, output string) (Index, error) {
	t.Helper()
	plugins := t.TempDir()
	testutil.InstallFakePlugin(t, plugins, "fakedeploy")
	description := pluginlib.DeploymentPackage{Reference: ref, Repository: "registry.example.com/team/app", Digest: "sha256:package"}
	opts := GenerateOptions{
		Plugins: plugins,
		DataDir: t.TempDir(),
		Output:  output,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return Generate(description, file, opts)
}

func TestGenerate(t *testing.T) {
	disabled := false
	file := File{Deployments: []Deployment{
		{Name: "backend", Type: "fakedeploy", Config: "/configs/backend.tmpl", Overlays: []string{"/configs/a.tmpl", "/configs/b.tmpl"}, Options: map[string]*Option{"release": option("api"), "chart": option("chart-b")}},
		{Name: "frontend", Type: "fakedeploy", DependsOn: []string{"backend"}},
		{Name: "skipped", Type: "missing", Enabled: &disabled},
	}}
	output := filepath.Join(t.TempDir(), "out")

	index, err := generateWith(t, file, output)

	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if index.Package != "registry.example.com/team/app@sha256:package" || len(index.Deployments) != 2 {
		t.Fatalf("index = %+v, want two deployments", index)
	}
	frontend := index.Deployments[1]
	if strings.Join(frontend.Files, ",") != "frontend/generated.json" || strings.Join(frontend.DependsOn, ",") != "backend" || frontend.Instructions != "apply frontend" {
		t.Errorf("frontend = %+v", frontend)
	}

	data, err := os.ReadFile(filepath.Join(output, "backend", "generated.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Name     string                      `json:"name"`
		Package  pluginlib.DeploymentPackage `json:"package"`
		Config   string                      `json:"config"`
		Overlays []string                    `json:"overlays"`
		Options  []string                    `json:"options"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "backend" || got.Package.Digest != "sha256:package" || got.Config != "/configs/backend.tmpl" {
		t.Errorf("the plugin got %+v", got)
	}
	if strings.Join(got.Overlays, ",") != "/configs/a.tmpl,/configs/b.tmpl" || strings.Join(got.Options, ",") != "chart=chart-b,release=api" {
		t.Errorf("overlays %q and options %q, want them in order and sorted", got.Overlays, got.Options)
	}

	written, err := os.ReadFile(filepath.Join(output, IndexFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(written), `"frontend/generated.json"`) {
		t.Errorf("%s = %s, want it to list what was generated", IndexFile, written)
	}
}

// TestGenerateLeavesOutputAsItWasOnFailure covers a deployment failing
// after another succeeded: neither shows in the output.
func TestGenerateLeavesOutputAsItWasOnFailure(t *testing.T) {
	for name, env := range map[string]string{
		"a plugin failing":        "FAKEDEPLOY_FAIL",
		"a file the plugin hides": "FAKEDEPLOY_UNREPORTED",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env, "second")
			file := File{Deployments: []Deployment{
				{Name: "first", Type: "fakedeploy"},
				{Name: "second", Type: "fakedeploy"},
			}}
			output := filepath.Join(t.TempDir(), "out")

			_, err := generateWith(t, file, output)

			if err == nil || !strings.Contains(err.Error(), `deployment "second"`) {
				t.Errorf("Generate = %v, want the second deployment's error", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Errorf("output exists after a failure: %v", err)
			}
		})
	}
}

func TestGenerateFindsEveryPluginFirst(t *testing.T) {
	file := File{Deployments: []Deployment{
		{Name: "first", Type: "fakedeploy"},
		{Name: "second", Type: "missing"},
	}}
	output := filepath.Join(t.TempDir(), "out")

	_, err := generateWith(t, file, output)

	if err == nil || !strings.Contains(err.Error(), "bomify-plugin-missing") {
		t.Errorf("Generate = %v, want the missing plugin named", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Errorf("output exists: %v", err)
	}
}

func TestGenerateRefusesNothingToGenerate(t *testing.T) {
	disabled := false
	file := File{Deployments: []Deployment{{Name: "only", Type: "fakedeploy", Enabled: &disabled}}}

	if _, err := generateWith(t, file, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Error("Generate with every deployment disabled succeeded")
	}
}
