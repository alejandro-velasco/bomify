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

	result, err := Pull(ref, outputDir, cdx.HashAlgoSHA256, testLogger())
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

func TestPullUnsupportedHashAlgorithm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0", DownloadURL: srv.URL}

	if _, err := Pull(ref, t.TempDir(), cdx.HashAlgoMD5, testLogger()); err == nil {
		t.Fatal("Pull() with an unsupported hash algorithm: expected error, got nil")
	}
}

func TestPullNonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0", DownloadURL: srv.URL}

	if _, err := Pull(ref, t.TempDir(), cdx.HashAlgoSHA256, testLogger()); err == nil {
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

func TestCheckPush(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	remote := srv.URL + "/upload/widget-1.0.bin"
	result, err := CheckPush(remote, testLogger())
	if err != nil {
		t.Fatalf("CheckPush() error = %v", err)
	}
	if result.OutputPath != remote {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, remote)
	}
	if gotMethod != http.MethodHead {
		t.Errorf("method = %s, want HEAD", gotMethod)
	}
}

// TestCheckPushNeverPuts proves CheckPush never falls back to a real PUT
// even when it can't conclusively verify write permission — the
// destination in this test doesn't implement HEAD at all (a common
// shape for a presigned upload URL), which must still be reported as a
// (caveated) success rather than tried as a real upload.
func TestCheckPushNeverPuts(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	result, err := CheckPush(srv.URL, testLogger())
	if err != nil {
		t.Fatalf("CheckPush() error = %v", err)
	}
	if gotMethod != http.MethodHead {
		t.Errorf("method = %s, want HEAD (never PUT)", gotMethod)
	}
	if result.OutputPath != srv.URL {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, srv.URL)
	}
}

func TestCheckPushRejectsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	if _, err := CheckPush(srv.URL, testLogger()); err == nil {
		t.Fatal("CheckPush() with a 401 response: expected error, got nil")
	}
}

func TestPush(t *testing.T) {
	const content = "the artifact's actual bytes"

	var (
		gotMethod        string
		gotBody          []byte
		gotContentLength int64
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentLength = r.ContentLength
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0", DownloadURL: srv.URL + "/widget-1.0.bin"}

	inputDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(inputDir, ref.Filename()), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	remote := srv.URL + "/upload/widget-1.0.bin"
	result, err := Push(inputDir, ref, remote, testLogger())
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	if result.OutputPath != remote {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, remote)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if string(gotBody) != content {
		t.Errorf("uploaded body = %q, want %q", gotBody, content)
	}
	if gotContentLength != int64(len(content)) {
		t.Errorf("Content-Length = %d, want %d", gotContentLength, len(content))
	}
}

func TestPushNonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ref := Ref{Name: "widget", Version: "1.0"}
	inputDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(inputDir, ref.Filename()), []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Push(inputDir, ref, srv.URL, testLogger()); err == nil {
		t.Fatal("Push() with a 500 response: expected error, got nil")
	}
}

func TestPushMissingLocalFile(t *testing.T) {
	ref := Ref{Name: "widget", Version: "1.0"}

	if _, err := Push(t.TempDir(), ref, "http://example.com", testLogger()); err == nil {
		t.Fatal("Push() with no local file in --input: expected error, got nil")
	}
}
