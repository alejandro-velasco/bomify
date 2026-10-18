package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestPull(t *testing.T) {
	const content = "the artifact's actual bytes"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0", DownloadURL: srv.URL + "/widget-1.0.bin"}
	outputDir := t.TempDir()

	result, err := Pull(ref, outputDir, testLogger())
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	wantPath := filepath.Join(outputDir, "widget-1.0.bin")
	if result.OutputPath != wantPath {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, wantPath)
	}

	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != content {
		t.Errorf("saved content = %q, want %q", got, content)
	}

	sum := sha256.Sum256([]byte(content))
	wantHash := hex.EncodeToString(sum[:])
	if result.Hash.Algorithm != cdx.HashAlgoSHA256 {
		t.Errorf("Hash.Algorithm = %q, want %q", result.Hash.Algorithm, cdx.HashAlgoSHA256)
	}
	if result.Hash.Value != wantHash {
		t.Errorf("Hash.Value = %q, want %q", result.Hash.Value, wantHash)
	}
}

func TestPullNonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0", DownloadURL: srv.URL}

	if _, err := Pull(ref, t.TempDir(), testLogger()); err == nil {
		t.Fatal("Pull() with a 404 response: expected error, got nil")
	}
}

func TestCheckPull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method = %s, want HEAD", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0", DownloadURL: srv.URL + "/widget-1.0.bin"}

	result, err := CheckPull(ref, testLogger())
	if err != nil {
		t.Fatalf("CheckPull() error = %v", err)
	}
	if result.OutputPath != ref.DownloadURL {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, ref.DownloadURL)
	}
}

func TestCheckPullNonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0", DownloadURL: srv.URL}

	if _, err := CheckPull(ref, testLogger()); err == nil {
		t.Fatal("CheckPull() with a 404 response: expected error, got nil")
	}
}
