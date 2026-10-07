package hub

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeHub serves org/model at testCommit over the Hub's API: its tree
// listing and its files, redirecting LFS files to a separate CDN server,
// as the Hub does.
type fakeHub struct {
	// Files is the repository's content, by path.
	Files map[string]string
	// LFS names the files stored in LFS.
	LFS map[string]bool
	// PageSize, if set, splits the listing into pages that long.
	PageSize int
	// Entries, if set, replaces the listing.
	Entries []treeEntry
	// Gated requires Token to download files.
	Gated bool
	Token string
	// Corrupt names a file served with one byte changed.
	Corrupt string
	// Info is the model info served for "main" and testCommit, with its
	// "sha" set to testCommit.
	Info map[string]any
	// BreakOnce names files whose first download is cut off halfway.
	BreakOnce map[string]bool

	hub, cdn *httptest.Server
	mutex    sync.Mutex
	// CDNAuthorization records each CDN request's Authorization header.
	CDNAuthorization []string
}

func startFakeHub(t *testing.T, fake *fakeHub) *fakeHub {
	t.Helper()
	fake.cdn = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fake.mutex.Lock()
		fake.CDNAuthorization = append(fake.CDNAuthorization, request.Header.Get("Authorization"))
		fake.mutex.Unlock()
		fake.serveContent(writer, strings.TrimPrefix(request.URL.Path, "/blob/"))
	}))
	fake.hub = httptest.NewServer(http.HandlerFunc(fake.serveHub))
	t.Cleanup(fake.hub.Close)
	t.Cleanup(fake.cdn.Close)
	return fake
}

func (f *fakeHub) client(token string) Client {
	client := Client{
		HTTP:     f.hub.Client(),
		Endpoint: f.hub.URL,
		Token:    token,
		Logger:   discardLogger(),
	}
	return client
}

func (f *fakeHub) entries() []treeEntry {
	if f.Entries != nil {
		return f.Entries
	}
	var entries []treeEntry
	for _, path := range slices.Sorted(mapsKeys(f.Files)) {
		content := f.Files[path]
		entry := treeEntry{
			Type: "file",
			Path: path,
			Size: int64(len(content)),
			OID:  gitBlobID(content),
		}
		if f.LFS[path] {
			sum := sha256.Sum256([]byte(content))
			entry.LFS = &struct {
				OID string `json:"oid"`
			}{OID: hex.EncodeToString(sum[:])}
			entry.OID = gitBlobID("pointer to " + path)
		}
		entries = append(entries, entry)
	}
	return entries
}

func (f *fakeHub) serveHub(writer http.ResponseWriter, request *http.Request) {
	treePrefix := "/api/models/org/model/tree/"
	resolvePrefix := "/org/model/resolve/" + testCommit + "/"
	infoPrefix := "/api/models/org/model/revision/"
	switch {
	case strings.HasPrefix(request.URL.Path, infoPrefix):
		revision := strings.TrimPrefix(request.URL.Path, infoPrefix)
		if revision != "main" && revision != testCommit {
			writer.Header().Set("X-Error-Message", "Invalid rev id")
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		info := map[string]any{"sha": testCommit}
		for key, value := range f.Info {
			info[key] = value
		}
		json.NewEncoder(writer).Encode(info)
	case strings.HasPrefix(request.URL.Path, treePrefix):
		if strings.TrimPrefix(request.URL.Path, treePrefix) != testCommit {
			writer.Header().Set("X-Error-Code", "RevisionNotFound")
			writer.Header().Set("X-Error-Message", "Invalid rev id")
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		entries := f.entries()
		if f.PageSize > 0 {
			start, _ := strconv.Atoi(request.URL.Query().Get("cursor"))
			end := min(start+f.PageSize, len(entries))
			if end < len(entries) {
				writer.Header().Set("Link", fmt.Sprintf(`<%s%s?recursive=true&cursor=%d>; rel="next"`, f.hub.URL, request.URL.Path, end))
			}
			entries = entries[start:end]
		}
		json.NewEncoder(writer).Encode(entries)
	case strings.HasPrefix(request.URL.Path, resolvePrefix):
		if f.Gated && request.Header.Get("Authorization") != "Bearer "+f.Token {
			writer.Header().Set("X-Error-Code", "GatedRepo")
			writer.Header().Set("X-Error-Message", "Access to model org/model is restricted.")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(request.URL.Path, resolvePrefix)
		if f.LFS[path] {
			http.Redirect(writer, request, f.cdn.URL+"/blob/"+path, http.StatusFound)
			return
		}
		f.serveContent(writer, path)
	default:
		http.NotFound(writer, request)
	}
}

func (f *fakeHub) serveContent(writer http.ResponseWriter, path string) {
	content, ok := f.Files[path]
	if !ok {
		http.NotFound(writer, nil)
		return
	}
	if path == f.Corrupt {
		content = "X" + content[1:]
	}
	f.mutex.Lock()
	broken := f.BreakOnce[path]
	delete(f.BreakOnce, path)
	f.mutex.Unlock()
	if broken {
		// Promise the whole file, send half, and hang up.
		writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
		writer.Write([]byte(content[:len(content)/2]))
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err == nil {
			connection.Close()
		}
		return
	}
	writer.Write([]byte(content))
}

func gitBlobID(content string) string {
	sum := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00%s", len(content), content)))
	return hex.EncodeToString(sum[:])
}

func mapsKeys(files map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for key := range files {
			if !yield(key) {
				return
			}
		}
	}
}

func testFiles() map[string]string {
	files := map[string]string{
		"config.json":            `{"model_type": "gpt2"}`,
		"model.safetensors":      "weights",
		"tokenizer/vocab.json":   `{"a": 1}`,
		"onnx/model.onnx":        "graph",
		"special tokens map.txt": "spaces in the name",
	}
	return files
}

func TestListFilesFollowsPages(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{
		Files:    testFiles(),
		PageSize: 2,
	})

	files, err := fake.client("").ListFiles(context.Background(), testRef())
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(files) != len(testFiles()) {
		t.Errorf("listed %d files, want %d", len(files), len(testFiles()))
	}
}

func TestListFilesRejectsPathsOutsideRepository(t *testing.T) {
	for _, path := range []string{"../escape", "/etc/passwd", `dir\file`, "a/../../b"} {
		entry := treeEntry{
			Type: "file",
			Path: path,
		}
		fake := startFakeHub(t, &fakeHub{Entries: []treeEntry{entry}})

		_, err := fake.client("").ListFiles(context.Background(), testRef())
		if err == nil || !strings.Contains(err.Error(), "outside the repository") {
			t.Errorf("ListFiles with %q = %v, want it refused", path, err)
		}
	}
}

func TestListFilesKeepsTokenOnHub(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{Files: testFiles()})
	elsewhere := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		t.Errorf("token sent to %s", request.URL)
	}))
	defer elsewhere.Close()
	hub := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Link", fmt.Sprintf(`<%s/next>; rel="next"`, elsewhere.URL))
		writer.Write([]byte("[]"))
	}))
	defer hub.Close()
	client := fake.client("hf_secret")
	client.Endpoint = hub.URL

	_, err := client.ListFiles(context.Background(), testRef())
	if err == nil || !strings.Contains(err.Error(), "continues at") {
		t.Errorf("ListFiles = %v, want the foreign page refused", err)
	}
}

func TestDownloadRejectsCorruptContent(t *testing.T) {
	for _, path := range []string{"config.json", "model.safetensors"} {
		fake := startFakeHub(t, &fakeHub{
			Files:   testFiles(),
			LFS:     map[string]bool{"model.safetensors": true},
			Corrupt: path,
		})
		files, err := fake.client("").ListFiles(context.Background(), testRef())
		if err != nil {
			t.Fatal(err)
		}
		index := slices.IndexFunc(files, func(file File) bool { return file.Path == path })
		dir := t.TempDir()

		err = fake.client("").Download(context.Background(), testRef(), files[index], dir)
		if err == nil || !strings.Contains(err.Error(), "hashing to") {
			t.Errorf("Download(%s) = %v, want a hash mismatch", path, err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, path)); !os.IsNotExist(statErr) {
			t.Errorf("corrupt %s left on disk: %v", path, statErr)
		}
	}
}
