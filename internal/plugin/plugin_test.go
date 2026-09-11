package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
		{"docker purl", cdx.Component{Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:docker/nginx@1.27.0"}, "docker"},
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
	baseDir := t.TempDir()

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	result, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256)
	if err != nil {
		t.Fatalf("Pull returned error: %v", err)
	}

	want := filepath.ToSlash(filepath.Join(componentDir(baseDir, component), "nginx-1.27.tar"))
	if got := filepath.ToSlash(result.OutputPath); got != want {
		t.Errorf("OutputPath = %q, want %q", got, want)
	}
}

func TestPullFailureRemovesComponentDir(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{Name: "fail-me", Version: "1.0.0"}

	if _, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256); err == nil {
		t.Fatal("Pull() with failing plugin: expected error, got nil")
	}

	if _, err := os.Stat(componentDir(baseDir, component)); !os.IsNotExist(err) {
		t.Errorf("componentDir still exists after failed Pull: %v", err)
	}
}

func TestPullHashMatch(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{
		Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27",
		Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "fakehash-nginx-1.27"}},
	}

	if _, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256); err != nil {
		t.Fatalf("Pull returned error: %v", err)
	}
}

func TestPullHashMismatchFails(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{
		Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27",
		Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "some-other-hash"}},
	}

	if _, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256); err == nil {
		t.Fatal("Pull() with mismatched hash: expected error, got nil")
	}

	if _, err := os.Stat(componentDir(baseDir, component)); !os.IsNotExist(err) {
		t.Errorf("componentDir still exists after hash mismatch: %v", err)
	}
}

func TestPullHashSkippedWhenSBOMHasNoDeclaredHash(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	// No Hashes on the component at all: the plugin still reports one, but
	// there's nothing in the SBOM to compare it against, so it's fine.
	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	if _, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256); err != nil {
		t.Fatalf("Pull returned error: %v", err)
	}
}

func TestPullHashSkippedWhenPluginOmitsHash(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	// "nohash-" tells fakeplugin to omit Hash, simulating a plugin that
	// can't compute the requested algorithm. A declared-but-wrong SBOM
	// hash must not cause a failure since there's nothing to compare.
	component := cdx.Component{
		Name: "nohash-nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27",
		Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: "some-other-hash"}},
	}

	if _, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256); err != nil {
		t.Fatalf("Pull returned error: %v", err)
	}
}

func TestNormalizeHashAlgorithm(t *testing.T) {
	tests := []struct {
		in   string
		want cdx.HashAlgorithm
	}{
		{"sha-256", cdx.HashAlgoSHA256},
		{"sha256", cdx.HashAlgoSHA256},
		{"SHA-256", cdx.HashAlgoSHA256},
		{"md5", cdx.HashAlgoMD5},
	}

	for _, tt := range tests {
		got, err := NormalizeHashAlgorithm(tt.in)
		if err != nil {
			t.Errorf("NormalizeHashAlgorithm(%q) returned error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeHashAlgorithm(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeHashAlgorithmUnrecognized(t *testing.T) {
	if _, err := NormalizeHashAlgorithm("not-a-real-algorithm"); err == nil {
		t.Fatal("NormalizeHashAlgorithm() with bogus input: expected error, got nil")
	}
}

func TestPush(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	// Simulate a prior successful Pull, which Push requires.
	if err := os.MkdirAll(componentDir(baseDir, component), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	result, err := Push(bin, component, baseDir, "registry.example.com/mirror")
	if err != nil {
		t.Fatalf("Push returned error: %v", err)
	}

	if want := "registry.example.com/mirror/nginx:1.27"; result.OutputPath != want {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, want)
	}
}

func TestPushWithoutPriorPull(t *testing.T) {
	bin := buildFakePlugin(t)

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	if _, err := Push(bin, component, t.TempDir(), "registry.example.com/mirror"); err == nil {
		t.Fatal("Push() with no prior Pull: expected error, got nil")
	}
}

func TestPushFailure(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{Name: "fail-me", Version: "1.0.0"}

	if err := os.MkdirAll(componentDir(baseDir, component), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	if _, err := Push(bin, component, baseDir, "registry.example.com/mirror"); err == nil {
		t.Fatal("Push() with failing plugin: expected error, got nil")
	}
}

func TestComponentDir(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "base")

	a := cdx.Component{PackageURL: "pkg:oci/nginx@1.27"}
	b := cdx.Component{PackageURL: "pkg:oci/redis@7.2.14"}

	if got, want := componentDir(baseDir, a), componentDir(baseDir, a); got != want {
		t.Errorf("componentDir() is not deterministic: %q != %q", got, want)
	}

	if componentDir(baseDir, a) == componentDir(baseDir, b) {
		t.Error("componentDir() collided for two different purls")
	}

	if got := componentDir(baseDir, a); !strings.HasPrefix(got, baseDir) {
		t.Errorf("componentDir() = %q, want it under baseDir %q", got, baseDir)
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
