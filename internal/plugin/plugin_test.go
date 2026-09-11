package plugin

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name      string
		component cdx.Component
		want      string
	}{
		{"container type", cdx.Component{Type: cdx.ComponentTypeContainer}, "docker"},
		{"oci purl", cdx.Component{Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:oci/nginx@sha256:abc"}, "docker"},
		{"docker purl", cdx.Component{Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:docker/nginx@1.27"}, "docker"},
		{"unrelated library", cdx.Component{Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/left-pad@1.3.0"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := Detect(tt.component); err != nil {
				t.Errorf("Detect() error = %v", err)
			} else if got != tt.want {
				t.Errorf("Detect() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBinaryName(t *testing.T) {
	if got, want := BinaryName("docker"), "bomify-plugin-docker"; got != want {
		t.Errorf("BinaryName() = %q, want %q", got, want)
	}
}

func TestFindMissing(t *testing.T) {
	if _, err := Find("does-not-exist-kind"); err == nil {
		t.Fatal("Find() for nonexistent plugin: expected error, got nil")
	}
}

func TestPull(t *testing.T) {
	bin := buildFakePlugin(t)
	outputDir := filepath.ToSlash(t.TempDir())

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	result, err := Pull(bin, component, outputDir)
	if err != nil {
		t.Fatalf("Pull returned error: %v", err)
	}

	want := outputDir + "/nginx-1.27.tar"
	if got := filepath.ToSlash(result.OutputPath); got != want {
		t.Errorf("OutputPath = %q, want %q", got, want)
	}
}

func TestPullFailure(t *testing.T) {
	bin := buildFakePlugin(t)

	component := cdx.Component{Name: "fail-me", Version: "1.0.0"}

	if _, err := Pull(bin, component, t.TempDir()); err == nil {
		t.Fatal("Pull() with failing plugin: expected error, got nil")
	}
}

func TestPush(t *testing.T) {
	bin := buildFakePlugin(t)

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	result, err := Push(bin, component, "registry.example.com/mirror")
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}

	if want := "registry.example.com/mirror/nginx:1.27"; result.OutputPath != want {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, want)
	}
}

func TestPushFailure(t *testing.T) {
	bin := buildFakePlugin(t)

	component := cdx.Component{Name: "fail-me", Version: "1.0.0"}

	if _, err := Push(bin, component, "registry.example.com/mirror"); err == nil {
		t.Fatal("Push() with failing plugin: expected error, got nil")
	}
}

// buildFakePlugin compiles testdata/fakeplugin into a temp directory and
// returns the resulting binary's path, standing in for a real
// bomify-plugin-* executable.
func buildFakePlugin(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "fakeplugin")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", bin, "./testdata/fakeplugin")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake plugin: %v\n%s", err, out)
	}

	return bin
}
