package chart

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	fakeregistry "github.com/google/go-containerregistry/pkg/registry"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	helmregistry "helm.sh/helm/v3/pkg/registry"
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

func TestChartHash(t *testing.T) {
	hash, err := chartHash(cdx.HashAlgoSHA256, []byte("chart contents"))
	if err != nil {
		t.Fatalf("chartHash() error = %v", err)
	}

	if hash.Algorithm != cdx.HashAlgoSHA256 {
		t.Errorf("Algorithm = %q, want %q", hash.Algorithm, cdx.HashAlgoSHA256)
	}
	if want := "48d492eade212236b0c6bb101caaab594b0b6721b14afe1d0df72182738ab8e6"; hash.Value != want {
		t.Errorf("Value = %q, want %q", hash.Value, want)
	}
}

func TestChartHashUnsupportedAlgorithm(t *testing.T) {
	if _, err := chartHash(cdx.HashAlgoMD5, []byte("chart contents")); err == nil {
		t.Fatal("chartHash() with an unsupported algorithm: expected error, got nil")
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

// TestOCIPushThenPullRoundTrip exercises Push and Pull against a real
// in-process OCI registry, using the real Helm SDK push/pull actions (not
// mocked): it proves a chart pushed there lands at the expected
// "<remote>/<name>:<version>" reference, and that pulling it back by that
// same name and version returns the exact chart that was pushed.
func TestOCIPushThenPullRoundTrip(t *testing.T) {
	usePlainHTTPRegistryClient(t)
	host := newTestOCIRegistry(t)

	const name, version = "widget", "1.2.3"
	remote := "oci://" + host + "/charts"

	inputDir := t.TempDir()
	wantContent := buildTestChart(t, inputDir, name, version)

	pushRef := Ref{Name: name, Version: version, RepositoryURL: remote, OCI: true}
	pushResult, err := Push(inputDir, pushRef, remote, testLogger())
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	wantDst := remote + "/" + name + ":" + version
	if pushResult.OutputPath != wantDst {
		t.Errorf("Push() OutputPath = %q, want %q", pushResult.OutputPath, wantDst)
	}

	outputDir := t.TempDir()
	pullRef := Ref{Name: name, Version: version, RepositoryURL: remote, OCI: true}
	pullResult, err := Pull(pullRef, outputDir, cdx.HashAlgoSHA256, testLogger())
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	wantPath := filepath.Join(outputDir, pullRef.Filename())
	if pullResult.OutputPath != wantPath {
		t.Errorf("Pull() OutputPath = %q, want %q", pullResult.OutputPath, wantPath)
	}

	gotContent, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", wantPath, err)
	}
	if string(gotContent) != string(wantContent) {
		t.Error("pulled chart content does not match the chart that was pushed")
	}

	wantSum := sha256.Sum256(wantContent)
	if pullResult.Hash.Algorithm != cdx.HashAlgoSHA256 {
		t.Errorf("Pull() Hash.Algorithm = %q, want %q", pullResult.Hash.Algorithm, cdx.HashAlgoSHA256)
	}
	if want := hex.EncodeToString(wantSum[:]); pullResult.Hash.Value != want {
		t.Errorf("Pull() Hash.Value = %q, want %q", pullResult.Hash.Value, want)
	}
}
