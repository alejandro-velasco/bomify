package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"golang.org/x/sync/errgroup"
)

// pushBranch is the branch push commits to.
const pushBranch = "main"

// batchSize is how many files one preupload or LFS batch request covers,
// as huggingface_hub sends them.
const batchSize = 256

// sampleSize is how much of a file preupload sends, for the Hub to tell
// text from binary.
const sampleSize = 512

// lfsHeaders are the Git LFS batch API's content types.
var lfsHeaders = http.Header{
	"Accept":       {"application/vnd.git-lfs+json"},
	"Content-Type": {"application/vnd.git-lfs+json"},
}

// localFile is one file push uploads.
type localFile struct {
	// Path is its "/"-separated path in the repository.
	Path   string
	Size   int64
	SHA256 string
	// BlobID is its Git blob ID (see File.BlobID), to compare it with a
	// file the Hub stores in Git.
	BlobID string
	// Sample is its first sampleSize bytes.
	Sample []byte
	// LFS is set when preupload says to upload it through LFS, rather than
	// inline in the commit.
	LFS bool
	// Ignored is set when preupload says the repository's .gitignore
	// excludes it, so it's left out of the commit.
	Ignored bool
}

// scanLocalFiles returns every file in dir, with its hash and sample.
func scanLocalFiles(dir string) ([]localFile, error) {
	paths, err := localPaths(dir)
	if err != nil {
		return nil, err
	}

	files := make([]localFile, 0, len(paths))
	for _, path := range paths {
		file, err := scanLocalFile(dir, path)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func scanLocalFile(dir, path string) (localFile, error) {
	opened, err := os.Open(filepath.Join(dir, filepath.FromSlash(path)))
	if err != nil {
		return localFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil {
		return localFile{}, fmt.Errorf("read %s: %w", path, err)
	}

	var sample bytes.Buffer
	content := sha256.New()
	blob, _ := verifier(File{Size: info.Size()})
	sampler := limitedWriter{
		buffer: &sample,
		limit:  sampleSize,
	}
	size, err := io.Copy(io.MultiWriter(content, blob, &sampler), opened)
	if err != nil {
		return localFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	if size != info.Size() {
		return localFile{}, fmt.Errorf("read %s: it changed while being read", path)
	}

	file := localFile{
		Path:   path,
		Size:   size,
		SHA256: hex.EncodeToString(content.Sum(nil)),
		BlobID: hex.EncodeToString(blob.Sum(nil)),
		Sample: sample.Bytes(),
	}
	return file, nil
}

// limitedWriter keeps the first limit bytes written to it, discarding the
// rest.
type limitedWriter struct {
	buffer *bytes.Buffer
	limit  int
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if room := w.limit - w.buffer.Len(); room > 0 {
		w.buffer.Write(data[:min(room, len(data))])
	}
	return len(data), nil
}

// CreateRepo creates repoID, a private model repository, unless it
// exists. A token allowed to write to repoID but not to create
// repositories gets a 401 or 403, so then repoID only has to exist.
func (c Client) CreateRepo(ctx context.Context, namespace, name string) error {
	payload := map[string]string{
		"name":         name,
		"organization": namespace,
		"type":         "model",
		"visibility":   "private",
	}
	request := call{
		Method: http.MethodPost,
		URL:    c.Endpoint + "/api/repos/create",
	}
	err := c.sendJSON(ctx, request, payload, nil)

	var statusErr *StatusError
	if !errors.As(err, &statusErr) {
		return err
	}
	switch statusErr.StatusCode {
	case http.StatusConflict:
		return nil
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
		info, infoErr := c.get(ctx, http.MethodGet, fmt.Sprintf("%s/api/models/%s/%s", c.Endpoint, namespace, name))
		if infoErr != nil {
			return err
		}
		info.Body.Close()
		return nil
	default:
		return err
	}
}

// preupload asks the Hub which of files to upload through LFS and which
// the repository's .gitignore excludes, setting their LFS and Ignored.
// An empty file always goes inline, since LFS storage refuses one.
func (c Client) preupload(ctx context.Context, repoID string, files []localFile) error {
	type preuploadFile struct {
		Path   string `json:"path"`
		Sample string `json:"sample"`
		Size   int64  `json:"size"`
	}
	type preuploadResponse struct {
		Files []struct {
			Path         string `json:"path"`
			UploadMode   string `json:"uploadMode"`
			ShouldIgnore bool   `json:"shouldIgnore"`
		} `json:"files"`
	}

	for batch := range slices.Chunk(files, batchSize) {
		requested := make([]preuploadFile, 0, len(batch))
		for _, file := range batch {
			entry := preuploadFile{
				Path:   file.Path,
				Sample: base64.StdEncoding.EncodeToString(file.Sample),
				Size:   file.Size,
			}
			requested = append(requested, entry)
		}
		request := call{
			Method: http.MethodPost,
			URL:    fmt.Sprintf("%s/api/models/%s/preupload/%s", c.Endpoint, repoID, pushBranch),
		}
		var response preuploadResponse
		if err := c.sendJSON(ctx, request, map[string]any{"files": requested}, &response); err != nil {
			return err
		}

		modes := map[string]int{}
		for index, answer := range response.Files {
			modes[answer.Path] = index
		}
		for index := range batch {
			answerIndex, ok := modes[batch[index].Path]
			if !ok {
				return fmt.Errorf("the Hub's preupload answer leaves out %s", batch[index].Path)
			}
			answer := response.Files[answerIndex]
			batch[index].LFS = answer.UploadMode == "lfs" && batch[index].Size > 0
			batch[index].Ignored = answer.ShouldIgnore
		}
	}
	return nil
}

// lfsAction is one step the LFS batch API tells a client to take.
type lfsAction struct {
	Href string `json:"href"`
	// Header holds a multipart upload's "chunk_size" and its parts' URLs,
	// keyed by part number.
	Header map[string]any `json:"header"`
}

type lfsObject struct {
	OID     string `json:"oid"`
	Size    int64  `json:"size"`
	Actions struct {
		Upload *lfsAction `json:"upload"`
		Verify *lfsAction `json:"verify"`
	} `json:"actions"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// uploadLFS uploads every file of files that goes through LFS and isn't
// ignored, concurrentTransfers at a time. A file the Hub already stores
// gets no upload action, so it's skipped.
func (c Client) uploadLFS(ctx context.Context, repoID, dir string, files []localFile) error {
	var pending []localFile
	for _, file := range files {
		if file.LFS && !file.Ignored {
			pending = append(pending, file)
		}
	}

	for batch := range slices.Chunk(pending, batchSize) {
		objects, err := c.lfsBatch(ctx, repoID, batch)
		if err != nil {
			return err
		}
		bySHA := map[string]localFile{}
		for _, file := range batch {
			bySHA[file.SHA256] = file
		}

		group, groupCtx := errgroup.WithContext(ctx)
		group.SetLimit(concurrentTransfers)
		for _, object := range objects {
			file, ok := bySHA[object.OID]
			if !ok {
				return fmt.Errorf("the Hub's LFS batch answer names %s, which wasn't asked for", object.OID)
			}
			if object.Error != nil {
				return fmt.Errorf("upload %s: %s (%d)", file.Path, object.Error.Message, object.Error.Code)
			}
			if object.Actions.Upload == nil {
				c.Logger.Info("already on the Hub", "file", file.Path)
				continue
			}
			group.Go(func() error {
				return c.uploadObject(groupCtx, dir, file, object)
			})
		}
		if err := group.Wait(); err != nil {
			return err
		}
	}
	return nil
}

// lfsBatch asks the Git LFS batch API how to upload files.
func (c Client) lfsBatch(ctx context.Context, repoID string, files []localFile) ([]lfsObject, error) {
	type object struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	}
	objects := make([]object, 0, len(files))
	for _, file := range files {
		objects = append(objects, object{OID: file.SHA256, Size: file.Size})
	}
	payload := map[string]any{
		"operation": "upload",
		"transfers": []string{"basic", "multipart"},
		"objects":   objects,
		"hash_algo": "sha256",
		"ref":       map[string]string{"name": pushBranch},
	}
	request := call{
		Method: http.MethodPost,
		URL:    fmt.Sprintf("%s/%s.git/info/lfs/objects/batch", c.Endpoint, repoID),
		Header: lfsHeaders.Clone(),
	}
	var response struct {
		Objects []lfsObject `json:"objects"`
	}
	if err := c.sendJSON(ctx, request, payload, &response); err != nil {
		return nil, err
	}
	return response.Objects, nil
}

// uploadObject uploads file as object says: in one PUT, or, when its
// upload header has a "chunk_size", in parts; then verifies it, if asked.
func (c Client) uploadObject(ctx context.Context, dir string, file localFile, object lfsObject) error {
	opened, err := os.Open(filepath.Join(dir, filepath.FromSlash(file.Path)))
	if err != nil {
		return fmt.Errorf("upload %s: %w", file.Path, err)
	}
	defer opened.Close()

	upload := object.Actions.Upload
	if chunkSize, ok := upload.Header["chunk_size"]; ok {
		err = c.uploadParts(ctx, opened, file, upload, chunkSize)
	} else {
		// As huggingface_hub does, the upload header is ignored: the URL
		// is pre-signed.
		request := call{
			Method: http.MethodPut,
			URL:    upload.Href,
			Body:   opened,
			Size:   file.Size,
		}
		var response *http.Response
		response, err = c.send(ctx, request)
		if err == nil {
			response.Body.Close()
		}
	}
	if err != nil {
		return fmt.Errorf("upload %s: %w", file.Path, err)
	}

	if verify := object.Actions.Verify; verify != nil {
		request := call{
			Method: http.MethodPost,
			URL:    verify.Href,
		}
		payload := map[string]any{"oid": file.SHA256, "size": file.Size}
		if err := c.sendJSON(ctx, request, payload, nil); err != nil {
			return fmt.Errorf("verify %s: %w", file.Path, err)
		}
	}
	c.Logger.Info("uploaded", "file", file.Path, "bytes", file.Size)
	return nil
}

// uploadParts uploads file in chunkSize parts to the URLs upload's header
// lists by part number, then completes the upload at its Href with each
// part's ETag.
func (c Client) uploadParts(ctx context.Context, opened *os.File, file localFile, upload *lfsAction, chunkSize any) error {
	size, err := strconv.ParseInt(fmt.Sprint(chunkSize), 10, 64)
	if err != nil || size <= 0 {
		return fmt.Errorf("the Hub sent chunk_size %v, not a positive integer", chunkSize)
	}
	var partURLs []string
	for number := 1; ; number++ {
		partURL, ok := upload.Header[strconv.Itoa(number)].(string)
		if !ok {
			break
		}
		partURLs = append(partURLs, partURL)
	}
	if want := (file.Size + size - 1) / size; int64(len(partURLs)) != want {
		return fmt.Errorf("the Hub sent %d part URLs for %d parts", len(partURLs), want)
	}

	type part struct {
		PartNumber int    `json:"partNumber"`
		ETag       string `json:"etag"`
	}
	parts := make([]part, 0, len(partURLs))
	for index, partURL := range partURLs {
		offset := int64(index) * size
		length := min(size, file.Size-offset)
		request := call{
			Method: http.MethodPut,
			URL:    partURL,
			Body:   io.NewSectionReader(opened, offset, length),
			Size:   length,
		}
		response, err := c.send(ctx, request)
		if err != nil {
			return fmt.Errorf("part %d: %w", index+1, err)
		}
		response.Body.Close()
		etag := response.Header.Get("ETag")
		if etag == "" {
			return fmt.Errorf("part %d: no ETag in the response", index+1)
		}
		parts = append(parts, part{PartNumber: index + 1, ETag: etag})
	}

	request := call{
		Method: http.MethodPost,
		URL:    upload.Href,
		Header: lfsHeaders.Clone(),
	}
	payload := map[string]any{"oid": file.SHA256, "parts": parts}
	return c.sendJSON(ctx, request, payload, nil)
}

// commitLine is one line of the commit API's NDJSON body.
type commitLine struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// commitMaxFiles and commitMaxInlineBytes bound one commit, as
// huggingface_hub's do: the Hub refuses a commit with too many files, or
// too much inline content, which is sent base64-encoded in its body.
// Variables so tests can make them small.
var (
	commitMaxFiles             = 256
	commitMaxInlineBytes int64 = 100 << 20
)

// remoteState returns the commit repoID's pushBranch is at, and its
// files, or none for an empty repository.
func (c Client) remoteState(ctx context.Context, namespace, name string) (string, []File, error) {
	info, err := c.ModelInfo(ctx, namespace+"/"+name, pushBranch)
	var statusErr *StatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	ref := Ref{
		Namespace: namespace,
		Name:      name,
		Revision:  info.SHA,
	}
	files, err := c.ListFiles(ctx, ref)
	return info.SHA, files, err
}

// sameContent reports whether remote, as the Hub lists it, holds local's
// content: by SHA-256 for an LFS file, by Git blob ID otherwise.
func sameContent(local localFile, remote File) bool {
	if remote.SHA256 != "" {
		return remote.SHA256 == local.SHA256
	}
	return remote.BlobID == local.BlobID
}

// commitBatches splits files, leaving out ignored ones, into commits of
// at most commitMaxFiles files and commitMaxInlineBytes of inline
// content.
func commitBatches(files []localFile) [][]localFile {
	var batches [][]localFile
	var batch []localFile
	var inline int64
	for _, file := range files {
		if file.Ignored {
			continue
		}
		size := int64(0)
		if !file.LFS {
			size = file.Size
		}
		if len(batch) > 0 && (len(batch) == commitMaxFiles || inline+size > commitMaxInlineBytes) {
			batches = append(batches, batch)
			batch, inline = nil, 0
		}
		batch = append(batch, file)
		inline += size
	}
	if len(batch) > 0 {
		batches = append(batches, batch)
	}
	return batches
}

// commitBatch commits files on top of parent, the commit pushBranch was
// at, returning the new commit's hash and URL. If the commit fails, for
// instance because a retry found the first attempt had gone through and
// pushBranch had moved, it checks whether pushBranch now holds files, as
// that attempt would have left it, and if so carries on from there.
func (c Client) commitBatch(ctx context.Context, namespace, name, dir string, files []localFile, message, parent string) (string, string, error) {
	repoID := namespace + "/" + name
	commitOID, commitURL, err := c.commit(ctx, repoID, dir, files, message, parent)
	if err == nil {
		return commitOID, commitURL, nil
	}

	head, remote, stateErr := c.remoteState(ctx, namespace, name)
	if stateErr != nil || head == parent {
		return "", "", err
	}
	byPath := map[string]File{}
	for _, file := range remote {
		byPath[file.Path] = file
	}
	for _, file := range files {
		if remoteFile, ok := byPath[file.Path]; !ok || !sameContent(file, remoteFile) {
			return "", "", err
		}
	}
	c.Logger.Warn("the commit went through after all", "commit", head, "error", err)
	return head, fmt.Sprintf("%s/%s/commit/%s", c.Endpoint, repoID, head), nil
}

// commit commits files to repoID's pushBranch as one commit on top of
// parent (unless it's empty, for an empty repository), so the Hub
// refuses it if pushBranch has moved: LFS files by hash, after
// uploadLFS; the rest inline. It returns the commit's hash and URL.
func (c Client) commit(ctx context.Context, repoID, dir string, files []localFile, message, parent string) (string, string, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	headerValue := map[string]string{
		"summary":     message,
		"description": "",
	}
	if parent != "" {
		headerValue["parentCommit"] = parent
	}
	header := commitLine{
		Key:   "header",
		Value: headerValue,
	}
	if err := encoder.Encode(header); err != nil {
		return "", "", err
	}

	for _, file := range files {
		line := commitLine{
			Key: "lfsFile",
			Value: map[string]any{
				"path": file.Path,
				"algo": "sha256",
				"oid":  file.SHA256,
				"size": file.Size,
			},
		}
		if !file.LFS {
			content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file.Path)))
			if err != nil {
				return "", "", fmt.Errorf("read %s: %w", file.Path, err)
			}
			line = commitLine{
				Key: "file",
				Value: map[string]string{
					"path":     file.Path,
					"content":  base64.StdEncoding.EncodeToString(content),
					"encoding": "base64",
				},
			}
		}
		if err := encoder.Encode(line); err != nil {
			return "", "", err
		}
	}

	request := call{
		Method: http.MethodPost,
		URL:    fmt.Sprintf("%s/api/models/%s/commit/%s", c.Endpoint, repoID, pushBranch),
		Body:   bytes.NewReader(body.Bytes()),
		Size:   int64(body.Len()),
		Header: http.Header{"Content-Type": {"application/x-ndjson"}},
	}
	response, err := c.send(ctx, request)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	var committed struct {
		CommitOID string `json:"commitOid"`
		CommitURL string `json:"commitUrl"`
	}
	if err := json.NewDecoder(response.Body).Decode(&committed); err != nil {
		return "", "", fmt.Errorf("parse the commit response: %w", err)
	}
	return committed.CommitOID, committed.CommitURL, nil
}

// WhoAmI returns the name of the user or organization the token belongs
// to, failing without a token.
func (c Client) WhoAmI(ctx context.Context) (string, error) {
	if c.Token == "" {
		return "", errors.New(`no token: set HF_TOKEN, or store one with "bomify login <hub host> --verify=false"`)
	}
	response, err := c.get(ctx, http.MethodGet, c.Endpoint+"/api/whoami-v2")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var identity struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		return "", fmt.Errorf("parse whoami-v2's response: %w", err)
	}
	return identity.Name, nil
}
