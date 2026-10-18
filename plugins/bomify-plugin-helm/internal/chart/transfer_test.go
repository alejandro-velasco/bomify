package chart

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	fakeregistry "github.com/google/go-containerregistry/pkg/registry"
	helmchart "helm.sh/helm/v4/pkg/chart/v2"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"
	helmregistry "helm.sh/helm/v4/pkg/registry"
)

func TestRegistryHost(t *testing.T) {
	tests := []struct {
		name          string
		repositoryURL string
		want          string
	}{
		{"classic https repository", "https://charts.example.com/stable", "charts.example.com"},
		{"oci registry", "oci://registry.example.com/charts", "registry.example.com"},
		{"host with port", "oci://registry.example.com:5000/charts", "registry.example.com:5000"},
		{"unparseable URL", "://not a url", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registryHost(tt.repositoryURL); got != tt.want {
				t.Errorf("registryHost(%q) = %q, want %q", tt.repositoryURL, got, tt.want)
			}
		})
	}
}

func TestNewRegistryClientAnonymous(t *testing.T) {
	if _, err := newRegistryClient(""); err != nil {
		t.Fatalf("newRegistryClient(\"\") error = %v", err)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestOCIRegistry starts an in-process OCI registry (the same real
// distribution-API implementation used by bomify-plugin-oci's tests) and
// returns its host:port. usePlainHTTPRegistryClient must also be called,
// since — unlike go-containerregistry, which crane uses and which
// auto-detects "localhost"/"127.0.0.1" as plain HTTP — the Helm SDK's own
// OCI client defaults to HTTPS and needs that told to it explicitly.
func newTestOCIRegistry(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(fakeregistry.New(fakeregistry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "http://")
}

// usePlainHTTPRegistryClient swaps newRegistryClient, for the duration of
// the test, for one that talks plain HTTP — needed to reach
// newTestOCIRegistry — without touching the real, credential-aware
// constructor bomify-plugin-helm actually ships with.
func usePlainHTTPRegistryClient(t *testing.T) {
	t.Helper()

	original := newRegistryClient
	newRegistryClient = func(host string) (*helmregistry.Client, error) {
		return helmregistry.NewClient(helmregistry.ClientOptPlainHTTP())
	}
	t.Cleanup(func() { newRegistryClient = original })
}

// buildTestChart creates a real, valid Helm chart archive named and
// versioned per name/version directly into dir (via the Helm SDK's own
// chartutil.Save, not hand-rolled bytes), returning its contents.
func buildTestChart(t *testing.T, dir, name, version string) []byte {
	t.Helper()

	ch := &helmchart.Chart{
		Metadata: &helmchart.Metadata{
			APIVersion: helmchart.APIVersionV2,
			Name:       name,
			Version:    version,
		},
	}

	path, err := chartutil.Save(ch, dir)
	if err != nil {
		t.Fatalf("chartutil.Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return data
}

// pushTestChart builds a chart per name/version, as buildTestChart does,
// and pushes it to the OCI registry repositoryURL ("oci://host/path")
// names, at "<path>/<name>:<version>", returning its contents.
func pushTestChart(t *testing.T, repositoryURL, name, version string) []byte {
	t.Helper()

	data := buildTestChart(t, t.TempDir(), name, version)

	registryClient, err := newRegistryClient(registryHost(repositoryURL))
	if err != nil {
		t.Fatalf("newRegistryClient: %v", err)
	}
	ref := strings.TrimPrefix(repositoryURL, helmregistry.OCIScheme+"://") + "/" + name + ":" + version
	if _, err := registryClient.Push(data, ref); err != nil {
		t.Fatalf("push %s: %v", ref, err)
	}
	return data
}

// TestOCIPull exercises Pull against a real in-process OCI registry,
// using the real Helm SDK pull action (not mocked): it proves pulling a
// chart by name and version returns the exact chart pushed there.
func TestOCIPull(t *testing.T) {
	usePlainHTTPRegistryClient(t)
	host := newTestOCIRegistry(t)

	const name, version = "widget", "1.2.3"
	repositoryURL := "oci://" + host + "/charts"
	wantContent := pushTestChart(t, repositoryURL, name, version)

	outputDir := t.TempDir()
	ref := Ref{Name: name, Version: version, RepositoryURL: repositoryURL, OCI: true}
	result, err := Pull(ref, outputDir, testLogger())
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	wantPath := filepath.Join(outputDir, ref.Filename())
	if result.OutputPath != wantPath {
		t.Errorf("Pull() OutputPath = %q, want %q", result.OutputPath, wantPath)
	}

	gotContent, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", wantPath, err)
	}
	if string(gotContent) != string(wantContent) {
		t.Error("pulled chart content does not match the chart that was pushed")
	}

	wantSum := sha256.Sum256(wantContent)
	if result.Hash.Algorithm != cdx.HashAlgoSHA256 {
		t.Errorf("Pull() Hash.Algorithm = %q, want %q", result.Hash.Algorithm, cdx.HashAlgoSHA256)
	}
	if want := hex.EncodeToString(wantSum[:]); result.Hash.Value != want {
		t.Errorf("Pull() Hash.Value = %q, want %q", result.Hash.Value, want)
	}
}

// TestOCICheckPull exercises CheckPull against a real in-process OCI
// registry holding the chart.
func TestOCICheckPull(t *testing.T) {
	usePlainHTTPRegistryClient(t)
	host := newTestOCIRegistry(t)

	const name, version = "widget", "1.2.3"
	repositoryURL := "oci://" + host + "/charts"
	pushTestChart(t, repositoryURL, name, version)

	ref := Ref{Name: name, Version: version, RepositoryURL: repositoryURL, OCI: true}
	result, err := CheckPull(ref, testLogger())
	if err != nil {
		t.Fatalf("CheckPull() error = %v", err)
	}
	if want := repositoryURL + "/" + name + ":" + version; result.OutputPath != want {
		t.Errorf("CheckPull() OutputPath = %q, want %q", result.OutputPath, want)
	}
}

func TestOCICheckPullMissingChart(t *testing.T) {
	usePlainHTTPRegistryClient(t)
	host := newTestOCIRegistry(t)

	ref := Ref{Name: "does-not-exist", Version: "1.0.0", RepositoryURL: "oci://" + host + "/charts", OCI: true}
	if _, err := CheckPull(ref, testLogger()); err == nil {
		t.Fatal("CheckPull() for a chart never pushed: expected error, got nil")
	}
}

// newTestHTTPRepo starts an in-process HTTP chart repository serving a
// single index.yaml with the given content at "/index.yaml", and returns
// its base URL.
func newTestHTTPRepo(t *testing.T, indexYAML string) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.yaml" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(indexYAML))
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

func TestHTTPCheckPull(t *testing.T) {
	const digest = "48d492eade212236b0c6bb101caaab594b0b6721b14afe1d0df72182738ab8e6"
	const index = `apiVersion: v1
entries:
  widget:
    - name: widget
      version: 1.2.3
      urls:
        - widget-1.2.3.tgz
      digest: ` + digest + `
generated: "2024-01-01T00:00:00Z"
`

	base := newTestHTTPRepo(t, index)
	ref := Ref{Name: "widget", Version: "1.2.3", RepositoryURL: base, OCI: false}

	result, err := CheckPull(ref, testLogger())
	if err != nil {
		t.Fatalf("CheckPull() error = %v", err)
	}

	if want := base + "/widget-1.2.3.tgz"; result.OutputPath != want {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, want)
	}
	if result.Hash.Algorithm != cdx.HashAlgoSHA256 {
		t.Errorf("Hash.Algorithm = %q, want %q", result.Hash.Algorithm, cdx.HashAlgoSHA256)
	}
	if result.Hash.Value != digest {
		t.Errorf("Hash.Value = %q, want %q", result.Hash.Value, digest)
	}
}

func TestHTTPCheckPullMissingVersion(t *testing.T) {
	const index = `apiVersion: v1
entries:
  widget:
    - name: widget
      version: 1.2.3
      urls:
        - widget-1.2.3.tgz
generated: "2024-01-01T00:00:00Z"
`

	base := newTestHTTPRepo(t, index)
	ref := Ref{Name: "widget", Version: "9.9.9", RepositoryURL: base, OCI: false}

	if _, err := CheckPull(ref, testLogger()); err == nil {
		t.Fatal("CheckPull() for a version not in index.yaml: expected error, got nil")
	}
}
