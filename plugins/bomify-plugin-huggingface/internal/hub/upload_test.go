package hub

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// remoteFile is one file of the fake repository's main branch.
type remoteFile struct {
	Content string
	LFS     bool
}

// fakeUploadHub is a Hub holding my-org/model, accepting pushes the way
// the Hub does: repo creation (with an initial .gitattributes commit),
// model info and the tree listing of main, preupload (LFS for
// .safetensors and .bin files), the LFS batch API with a separate storage
// server standing in for pre-signed URLs, and the NDJSON commit API,
// refusing a commit whose parentCommit isn't main's head. Every hub
// endpoint wants Token.
type fakeUploadHub struct {
	Token string
	// Exists makes the repository exist from the start, holding Initial
	// and a .gitattributes.
	Exists  bool
	Initial map[string]string
	// CreateForbidden refuses creating repositories.
	CreateForbidden bool
	// Stored names objects, by SHA-256, the Hub already has.
	Stored map[string]bool
	// ChunkSize, if set, makes LFS uploads multipart.
	ChunkSize int64
	// Ignore names files the repository's .gitignore excludes.
	Ignore map[string]bool
	// StorageFailures fails that many storage requests first, with a 503.
	StorageFailures int
	// LoseCommitResponses applies that many commits but answers them with
	// a 503, as if the response were lost.
	LoseCommitResponses int
	// RefuseCommit, if set, refuses the commit with that number, counting
	// the first from 1, with a 400.
	RefuseCommit int

	hub, storage *httptest.Server
	mutex        sync.Mutex
	parts        map[string]map[int][]byte
	// Files is main's content, and Head its commit.
	Files map[string]remoteFile
	Head  string
	// Created records repository creation requests.
	Created []map[string]string
	// Uploaded records each object's content, by SHA-256.
	Uploaded map[string][]byte
	// Commits counts commit requests, and Applied the commits made.
	Commits, Applied int
	// Committed records every commit's NDJSON lines.
	Committed []commitLine
	// StorageAuthorization records each storage request's Authorization.
	StorageAuthorization []string
}

func startFakeUploadHub(t *testing.T, fake *fakeUploadHub) *fakeUploadHub {
	t.Helper()
	fake.parts = map[string]map[int][]byte{}
	fake.Uploaded = map[string][]byte{}
	if fake.Exists {
		fake.initialize()
		for path, content := range fake.Initial {
			fake.Files[path] = remoteFile{Content: content}
		}
	}
	fake.storage = httptest.NewTLSServer(http.HandlerFunc(fake.serveStorage))
	fake.hub = httptest.NewTLSServer(http.HandlerFunc(fake.serveHub))
	t.Cleanup(fake.hub.Close)
	t.Cleanup(fake.storage.Close)
	return fake
}

// initialize creates the repository as the Hub does, with one commit
// holding a .gitattributes.
func (f *fakeUploadHub) initialize() {
	f.Files = map[string]remoteFile{".gitattributes": {Content: "*.safetensors filter=lfs"}}
	f.Head = commitID(0)
}

func commitID(number int) string {
	return fmt.Sprintf("%040x", number+0xc0ffee)
}

func (f *fakeUploadHub) client(token string) Client {
	client := Client{
		HTTP:     f.hub.Client(),
		Endpoint: f.hub.URL,
		Token:    token,
		Logger:   discardLogger(),
	}
	return client
}

func (f *fakeUploadHub) remote() string {
	return f.hub.URL + "/my-org"
}

func isLFSPath(path string) bool {
	return strings.HasSuffix(path, ".safetensors") || strings.HasSuffix(path, ".bin")
}

func (f *fakeUploadHub) serveStorage(writer http.ResponseWriter, request *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.StorageAuthorization = append(f.StorageAuthorization, request.Header.Get("Authorization"))
	if request.ContentLength < 0 {
		http.Error(writer, "Content-Length required", http.StatusLengthRequired)
		return
	}
	body, _ := io.ReadAll(request.Body)
	if f.StorageFailures > 0 {
		f.StorageFailures--
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	// /put/<oid> or /part/<oid>/<number>
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	switch segments[0] {
	case "put":
		f.Uploaded[segments[1]] = body
	case "part":
		number, _ := strconv.Atoi(segments[2])
		if f.parts[segments[1]] == nil {
			f.parts[segments[1]] = map[int][]byte{}
		}
		f.parts[segments[1]][number] = body
		writer.Header().Set("ETag", fmt.Sprintf(`"etag-%d"`, number))
	}
}

func (f *fakeUploadHub) serveHub(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer "+f.Token {
		writer.Header().Set("X-Error-Message", "Invalid credentials")
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()

	switch path := request.URL.Path; {
	case path == "/api/whoami-v2":
		json.NewEncoder(writer).Encode(map[string]string{"name": "tester"})
	case path == "/api/repos/create":
		var payload map[string]string
		json.NewDecoder(request.Body).Decode(&payload)
		f.Created = append(f.Created, payload)
		switch {
		case f.CreateForbidden:
			writer.WriteHeader(http.StatusForbidden)
		case f.Files != nil:
			writer.WriteHeader(http.StatusConflict)
		default:
			f.initialize()
			json.NewEncoder(writer).Encode(map[string]string{"url": f.hub.URL + "/my-org/model"})
		}
	case path == "/api/models/my-org/model" || path == "/api/models/my-org/model/revision/main":
		if f.Files == nil {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		json.NewEncoder(writer).Encode(map[string]string{"sha": f.Head})
	case path == "/api/models/my-org/model/tree/"+f.Head:
		f.serveTree(writer)
	case path == "/api/models/my-org/model/preupload/main":
		var payload struct {
			Files []struct {
				Path string `json:"path"`
			} `json:"files"`
		}
		json.NewDecoder(request.Body).Decode(&payload)
		var answers []map[string]any
		for _, file := range payload.Files {
			mode := "regular"
			if isLFSPath(file.Path) {
				mode = "lfs"
			}
			answers = append(answers, map[string]any{"path": file.Path, "uploadMode": mode, "shouldIgnore": f.Ignore[file.Path]})
		}
		json.NewEncoder(writer).Encode(map[string]any{"files": answers})
	case path == "/my-org/model.git/info/lfs/objects/batch":
		f.serveLFSBatch(writer, request)
	case strings.HasPrefix(path, "/complete/"):
		f.serveComplete(writer, request, strings.TrimPrefix(path, "/complete/"))
	case path == "/verify":
		var payload struct {
			OID string `json:"oid"`
		}
		json.NewDecoder(request.Body).Decode(&payload)
		if _, ok := f.Uploaded[payload.OID]; !ok {
			http.Error(writer, "not uploaded", http.StatusNotFound)
		}
	case path == "/api/models/my-org/model/commit/main":
		f.serveCommit(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (f *fakeUploadHub) serveTree(writer http.ResponseWriter) {
	var entries []treeEntry
	for _, path := range slices.Sorted(func(yield func(string) bool) {
		for path := range f.Files {
			if !yield(path) {
				return
			}
		}
	}) {
		file := f.Files[path]
		entry := treeEntry{
			Type: "file",
			Path: path,
			Size: int64(len(file.Content)),
			OID:  gitBlobID(file.Content),
		}
		if file.LFS {
			entry.LFS = &struct {
				OID string `json:"oid"`
			}{OID: sha256Hex(file.Content)}
			entry.OID = gitBlobID("pointer to " + path)
		}
		entries = append(entries, entry)
	}
	json.NewEncoder(writer).Encode(entries)
}

func (f *fakeUploadHub) serveLFSBatch(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Accept") != "application/vnd.git-lfs+json" {
		http.Error(writer, "not an LFS request", http.StatusNotAcceptable)
		return
	}
	var payload struct {
		Objects []struct {
			OID  string `json:"oid"`
			Size int64  `json:"size"`
		} `json:"objects"`
	}
	json.NewDecoder(request.Body).Decode(&payload)
	var objects []map[string]any
	for _, object := range payload.Objects {
		answer := map[string]any{"oid": object.OID, "size": object.Size}
		if _, uploaded := f.Uploaded[object.OID]; !f.Stored[object.OID] && !uploaded {
			upload := map[string]any{"href": f.storage.URL + "/put/" + object.OID}
			if f.ChunkSize > 0 {
				header := map[string]any{"chunk_size": strconv.FormatInt(f.ChunkSize, 10)}
				for number := int64(1); number <= (object.Size+f.ChunkSize-1)/f.ChunkSize; number++ {
					header[strconv.FormatInt(number, 10)] = fmt.Sprintf("%s/part/%s/%d", f.storage.URL, object.OID, number)
				}
				upload = map[string]any{"href": f.hub.URL + "/complete/" + object.OID, "header": header}
			}
			answer["actions"] = map[string]any{
				"upload": upload,
				"verify": map[string]any{"href": f.hub.URL + "/verify"},
			}
		}
		objects = append(objects, answer)
	}
	json.NewEncoder(writer).Encode(map[string]any{"transfer": "basic", "objects": objects})
}

func (f *fakeUploadHub) serveComplete(writer http.ResponseWriter, request *http.Request, oid string) {
	var payload struct {
		Parts []struct {
			PartNumber int    `json:"partNumber"`
			ETag       string `json:"etag"`
		} `json:"parts"`
	}
	json.NewDecoder(request.Body).Decode(&payload)
	var assembled []byte
	for _, part := range payload.Parts {
		if part.ETag != fmt.Sprintf(`"etag-%d"`, part.PartNumber) {
			http.Error(writer, "wrong ETag", http.StatusBadRequest)
			return
		}
		assembled = append(assembled, f.parts[oid][part.PartNumber]...)
	}
	f.Uploaded[oid] = assembled
}

func (f *fakeUploadHub) serveCommit(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Content-Type") != "application/x-ndjson" {
		http.Error(writer, "not NDJSON", http.StatusBadRequest)
		return
	}
	f.Commits++
	if f.Commits == f.RefuseCommit {
		http.Error(writer, "refused", http.StatusBadRequest)
		return
	}

	var lines []commitLine
	scanner := bufio.NewScanner(request.Body)
	scanner.Buffer(nil, 1<<20)
	for scanner.Scan() {
		var line commitLine
		json.Unmarshal(scanner.Bytes(), &line)
		lines = append(lines, line)
	}
	header := lines[0].Value.(map[string]any)
	if parent, ok := header["parentCommit"]; ok && parent != f.Head {
		writer.Header().Set("X-Error-Message", "parent commit isn't the branch's head")
		writer.WriteHeader(http.StatusConflict)
		return
	}

	for _, line := range lines[1:] {
		value := line.Value.(map[string]any)
		path := value["path"].(string)
		switch line.Key {
		case "file":
			content, _ := base64.StdEncoding.DecodeString(value["content"].(string))
			f.Files[path] = remoteFile{Content: string(content)}
		case "lfsFile":
			content, ok := f.Uploaded[value["oid"].(string)]
			if !ok && !f.Stored[value["oid"].(string)] {
				http.Error(writer, "LFS object missing", http.StatusUnprocessableEntity)
				return
			}
			f.Files[path] = remoteFile{Content: string(content), LFS: true}
		}
	}
	f.Committed = append(f.Committed, lines...)
	f.Applied++
	f.Head = commitID(f.Applied)

	if f.LoseCommitResponses > 0 {
		f.LoseCommitResponses--
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(writer).Encode(map[string]string{"commitOid": f.Head, "commitUrl": f.hub.URL + "/my-org/model/commit/" + f.Head})
}

// committedFile returns the last commit line for path, if there's one.
func (f *fakeUploadHub) committedFile(path string) (commitLine, bool) {
	for _, line := range slices.Backward(f.Committed) {
		value, _ := line.Value.(map[string]any)
		if value["path"] == path {
			return line, true
		}
	}
	return commitLine{}, false
}

// noSleep makes retries immediate, recording each wait.
func noSleep(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	original := sleep
	sleep = func(_ context.Context, wait time.Duration) error {
		waits = append(waits, wait)
		return nil
	}
	t.Cleanup(func() { sleep = original })
	return &waits
}

// commitLimits sets commitMaxFiles and commitMaxInlineBytes for a test.
func commitLimits(t *testing.T, files int, inlineBytes int64) {
	t.Helper()
	originalFiles, originalBytes := commitMaxFiles, commitMaxInlineBytes
	commitMaxFiles, commitMaxInlineBytes = files, inlineBytes
	t.Cleanup(func() { commitMaxFiles, commitMaxInlineBytes = originalFiles, originalBytes })
}

func sha256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func pushInput(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"config.json":       `{"model_type": "gpt2"}`,
		"model.safetensors": "weights in safetensors",
		"onnx/model.bin":    "a bigger binary file",
		"empty.bin":         "",
		"notes.tmp":         "ignored by .gitignore",
	})
	return dir
}

// requireMirrors fails unless main holds exactly input's files, but for
// ignored ones and the Hub's .gitattributes.
func (f *fakeUploadHub) requireMirrors(t *testing.T, input string, ignored ...string) {
	t.Helper()
	paths, err := localPaths(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if slices.Contains(ignored, path) {
			if _, ok := f.Files[path]; ok {
				t.Errorf("main holds %s, which .gitignore excludes", path)
			}
			continue
		}
		if want := readTestFile(t, input, path); f.Files[path].Content != want {
			t.Errorf("main's %s = %q, want %q", path, f.Files[path].Content, want)
		}
	}
	for path := range f.Files {
		if path != ".gitattributes" && !slices.Contains(paths, path) {
			t.Errorf("main holds %s, which isn't in the input", path)
		}
	}
}

func TestPush(t *testing.T) {
	for name, chunkSize := range map[string]int64{"single PUT": 0, "multipart": 7} {
		t.Run(name, func(t *testing.T) {
			fake := startFakeUploadHub(t, &fakeUploadHub{
				Token:     "hf_write",
				ChunkSize: chunkSize,
				Ignore:    map[string]bool{"notes.tmp": true},
			})
			input := pushInput(t)

			result, err := Push(context.Background(), fake.client("hf_write"), testRef(), input, fake.remote(), discardLogger())
			if err != nil {
				t.Fatalf("Push: %v", err)
			}
			if want := strings.TrimPrefix(fake.remote(), "https://") + "/model@" + fake.Head; result.OutputPath != want {
				t.Errorf("OutputPath = %q, want %q", result.OutputPath, want)
			}
			fake.requireMirrors(t, input, "notes.tmp")

			if len(fake.Created) != 1 || fake.Created[0]["visibility"] != "private" || fake.Created[0]["organization"] != "my-org" {
				t.Errorf("created %v, want my-org/model, private", fake.Created)
			}
			for path, key := range map[string]string{"model.safetensors": "lfsFile", "onnx/model.bin": "lfsFile", "config.json": "file", "empty.bin": "file"} {
				if line, ok := fake.committedFile(path); !ok || line.Key != key {
					t.Errorf("commit line for %s = %+v, want %s", path, line, key)
				}
			}
			for _, authorization := range fake.StorageAuthorization {
				if authorization != "" {
					t.Errorf("storage saw Authorization %q, want the token kept on the hub", authorization)
				}
			}
		})
	}
}

func TestPushSkipsObjectsTheHubHas(t *testing.T) {
	input := pushInput(t)
	stored := sha256Hex(readTestFile(t, input, "model.safetensors"))
	fake := startFakeUploadHub(t, &fakeUploadHub{
		Token:  "hf_write",
		Stored: map[string]bool{stored: true},
	})

	if _, err := Push(context.Background(), fake.client("hf_write"), testRef(), input, fake.remote(), discardLogger()); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, uploaded := fake.Uploaded[stored]; uploaded {
		t.Error("uploaded model.safetensors, which the Hub already has")
	}
	if _, ok := fake.committedFile("model.safetensors"); !ok {
		t.Error("left model.safetensors out of the commit")
	}
}

func TestPushInBatches(t *testing.T) {
	for name, limits := range map[string]struct {
		files       int
		inlineBytes int64
		commits     int
	}{
		"by file count":     {files: 2, inlineBytes: 1 << 20, commits: 3},
		"by inline content": {files: 100, inlineBytes: 30, commits: 2},
	} {
		t.Run(name, func(t *testing.T) {
			commitLimits(t, limits.files, limits.inlineBytes)
			fake := startFakeUploadHub(t, &fakeUploadHub{Token: "hf_write"})
			input := pushInput(t)

			result, err := Push(context.Background(), fake.client("hf_write"), testRef(), input, fake.remote(), discardLogger())
			if err != nil {
				t.Fatalf("Push: %v", err)
			}
			if fake.Applied != limits.commits {
				t.Errorf("made %d commits, want %d", fake.Applied, limits.commits)
			}
			if !strings.HasSuffix(result.OutputPath, "@"+fake.Head) {
				t.Errorf("OutputPath = %q, want the last commit, %s", result.OutputPath, fake.Head)
			}
			fake.requireMirrors(t, input)
		})
	}
}

func TestPushResumes(t *testing.T) {
	commitLimits(t, 2, 1<<20)
	fake := startFakeUploadHub(t, &fakeUploadHub{
		Token:        "hf_write",
		RefuseCommit: 2,
	})
	input := pushInput(t)

	if _, err := Push(context.Background(), fake.client("hf_write"), testRef(), input, fake.remote(), discardLogger()); err == nil {
		t.Fatal("Push succeeded despite a refused commit")
	}
	if fake.Applied != 1 {
		t.Fatalf("made %d commits before the refusal, want 1", fake.Applied)
	}

	// The same push again only sends what the first didn't commit.
	committedBefore := len(fake.Committed)
	if _, err := Push(context.Background(), fake.client("hf_write"), testRef(), input, fake.remote(), discardLogger()); err != nil {
		t.Fatalf("Push again: %v", err)
	}
	fake.requireMirrors(t, input)
	for _, line := range fake.Committed[committedBefore:] {
		if value, ok := line.Value.(map[string]any); ok && line.Key != "header" && (value["path"] == "config.json" || value["path"] == "empty.bin") {
			t.Errorf("committed %s again, after the first push committed it", value["path"])
		}
	}

	// And once more commits nothing.
	applied, uploaded := fake.Applied, len(fake.Uploaded)
	result, err := Push(context.Background(), fake.client("hf_write"), testRef(), input, fake.remote(), discardLogger())
	if err != nil {
		t.Fatalf("Push a third time: %v", err)
	}
	if fake.Applied != applied || len(fake.Uploaded) != uploaded || result.Message != "already up to date" {
		t.Errorf("third push made %d commits and %d uploads (%q), want none", fake.Applied-applied, len(fake.Uploaded)-uploaded, result.Message)
	}
}

func TestPushRepositoryCreation(t *testing.T) {
	for _, tc := range []struct {
		name            string
		exists, refused bool
		wantErr         bool
	}{
		{name: "exists", exists: true},
		{name: "may write, not create", exists: true, refused: true},
		{name: "may not create, missing", refused: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := startFakeUploadHub(t, &fakeUploadHub{
				Token:           "hf_write",
				Exists:          tc.exists,
				CreateForbidden: tc.refused,
			})

			_, err := Push(context.Background(), fake.client("hf_write"), testRef(), pushInput(t), fake.remote(), discardLogger())
			if (err != nil) != tc.wantErr {
				t.Errorf("Push = %v, want error %t", err, tc.wantErr)
			}
		})
	}
}

func TestPushRefusesRepositoryWithOtherFiles(t *testing.T) {
	fake := startFakeUploadHub(t, &fakeUploadHub{
		Token:   "hf_write",
		Exists:  true,
		Initial: map[string]string{"other-model.bin": "something else"},
	})

	_, err := Push(context.Background(), fake.client("hf_write"), testRef(), pushInput(t), fake.remote(), discardLogger())
	if err == nil || !strings.Contains(err.Error(), "other-model.bin") {
		t.Errorf("Push = %v, want the repository's other file named", err)
	}
	if fake.Applied != 0 {
		t.Errorf("made %d commits, want none", fake.Applied)
	}
}

func TestPushRetries(t *testing.T) {
	waits := noSleep(t)
	fake := startFakeUploadHub(t, &fakeUploadHub{
		Token:               "hf_write",
		ChunkSize:           7,
		StorageFailures:     3,
		LoseCommitResponses: 1,
	})
	input := pushInput(t)

	if _, err := Push(context.Background(), fake.client("hf_write"), testRef(), input, fake.remote(), discardLogger()); err != nil {
		t.Fatalf("Push: %v", err)
	}
	fake.requireMirrors(t, input)
	// The commit whose response was lost is found applied, not repeated.
	if fake.Applied != 1 {
		t.Errorf("made %d commits, want 1", fake.Applied)
	}
	if len(*waits) < 4 {
		t.Errorf("waited %d times, want a retry per failure", len(*waits))
	}
}

func TestSendHonorsRetryAfter(t *testing.T) {
	waits := noSleep(t)
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		if attempts == 1 {
			writer.Header().Set("Retry-After", "3")
			writer.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer server.Close()
	client := Client{
		HTTP:     server.Client(),
		Endpoint: server.URL,
		Logger:   discardLogger(),
	}

	response, err := client.get(context.Background(), http.MethodGet, server.URL+"/api/anything")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	response.Body.Close()
	if len(*waits) != 1 || (*waits)[0] != 3*time.Second {
		t.Errorf("waited %v, want the 3s Retry-After asked for", *waits)
	}
}

func TestSendGivesUp(t *testing.T) {
	waits := noSleep(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	client := Client{
		HTTP:     server.Client(),
		Endpoint: server.URL,
		Logger:   discardLogger(),
	}

	_, err := client.get(context.Background(), http.MethodGet, server.URL+"/upload?X-Amz-Signature=secret")
	if err == nil || len(*waits) != len(retryWaits) {
		t.Errorf("get = %v after %d retries, want a failure after %d", err, len(*waits), len(retryWaits))
	}
	if strings.Contains(err.Error(), "secret") {
		t.Errorf("error %q includes the URL's signature", err)
	}
}

func TestCheckPush(t *testing.T) {
	fake := startFakeUploadHub(t, &fakeUploadHub{Token: "hf_write"})

	result, err := CheckPush(context.Background(), fake.client("hf_write"), testRef(), fake.remote())
	if err != nil {
		t.Fatalf("CheckPush: %v", err)
	}
	if !strings.Contains(result.Message, "authenticated as tester") {
		t.Errorf("Message = %q, want who the token belongs to", result.Message)
	}

	if _, err := CheckPush(context.Background(), fake.client(""), testRef(), fake.remote()); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Errorf("CheckPush without a token = %v, want it refused", err)
	}
	if _, err := CheckPush(context.Background(), fake.client("hf_wrong"), testRef(), fake.remote()); err == nil || !strings.Contains(err.Error(), "Invalid credentials") {
		t.Errorf("CheckPush with a bad token = %v, want the Hub's refusal", err)
	}
}

func readTestFile(t *testing.T, dir, path string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
