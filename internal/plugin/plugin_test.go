package plugin

import (
	"encoding/json"
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

	component := cdx.Component{Name: "fail-me", Version: "1.0.0", PackageURL: "fail-me"}

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
		Name: "nginx", Version: "1.27", PackageURL: "nohash-nginx",
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

func TestPullWritesManifest(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	if _, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256); err != nil {
		t.Fatalf("Pull returned error: %v", err)
	}

	data, err := os.ReadFile(manifestPath(baseDir, component))
	if err != nil {
		t.Fatalf("ReadFile manifest: %v", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal manifest: %v", err)
	}

	if m.Component.Name != "nginx" || m.Component.Version != "1.27" {
		t.Errorf("manifest component = %+v, want name=nginx version=1.27", m.Component)
	}

	if m.Component.Hashes == nil {
		t.Fatal("manifest component has no Hashes")
	}

	found := false
	for _, h := range *m.Component.Hashes {
		if h.Algorithm == cdx.HashAlgoSHA256 && h.Value == "fakehash-nginx-1.27" {
			found = true
		}
	}
	if !found {
		t.Errorf("manifest component Hashes = %+v, want the computed SHA-256 hash included", *m.Component.Hashes)
	}
}

func TestPullFailureDoesNotWriteManifest(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{Name: "fail-me", Version: "1.0.0", PackageURL: "fail-me"}

	if _, err := Pull(bin, component, baseDir, cdx.HashAlgoSHA256); err == nil {
		t.Fatal("Pull() with failing plugin: expected error, got nil")
	}

	if _, err := os.Stat(manifestPath(baseDir, component)); !os.IsNotExist(err) {
		t.Errorf("manifest exists after failed Pull: %v", err)
	}
}

func TestMergeHash(t *testing.T) {
	existing := []cdx.Hash{{Algorithm: cdx.HashAlgoMD5, Value: "existing-md5"}}

	got := mergeHash(&existing, Hash{Algorithm: cdx.HashAlgoSHA256, Value: "new-sha256"})
	if got == nil || len(*got) != 2 {
		t.Fatalf("mergeHash() append = %v, want 2 entries", got)
	}

	got = mergeHash(got, Hash{Algorithm: cdx.HashAlgoMD5, Value: "updated-md5"})
	if got == nil || len(*got) != 2 {
		t.Fatalf("mergeHash() replace = %v, want 2 entries", got)
	}
	for _, h := range *got {
		if h.Algorithm == cdx.HashAlgoMD5 && h.Value != "updated-md5" {
			t.Errorf("MD5 value = %q, want %q", h.Value, "updated-md5")
		}
	}

	got = mergeHash(nil, Hash{Algorithm: cdx.HashAlgoSHA256, Value: "only"})
	if got == nil || len(*got) != 1 {
		t.Fatalf("mergeHash(nil, ...) = %v, want 1 entry", got)
	}
}

// simulatePriorPull creates baseDir's component directory and manifest as
// a successful Pull would, so Push has something to find.
func simulatePriorPull(t *testing.T, baseDir string, component cdx.Component) {
	t.Helper()

	if err := os.MkdirAll(componentDir(baseDir, component), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := writeManifest(baseDir, component, Hash{}); err != nil {
		t.Fatalf("writeManifest: %v", err)
	}
}

func TestPush(t *testing.T) {
	bin := buildFakePlugin(t)
	baseDir := t.TempDir()

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	simulatePriorPull(t, baseDir, component)

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

	component := cdx.Component{Name: "fail-me", Version: "1.0.0", PackageURL: "fail-me"}

	simulatePriorPull(t, baseDir, component)

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
