package hub

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// File is one file of a repository at a commit, as the Hub lists it.
type File struct {
	// Path is the file's path in the repository, "/"-separated.
	Path string
	// Size is its size in bytes.
	Size int64
	// SHA256 is an LFS file's SHA-256, or "" for a file stored in Git.
	SHA256 string
	// BlobID is a file stored in Git's blob ID: the SHA-1 of
	// "blob <size>\x00" and its content. Unused for an LFS file.
	BlobID string
}

// treeEntry is one entry of the Hub's tree listing.
type treeEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	OID  string `json:"oid"`
	LFS  *struct {
		OID string `json:"oid"`
	} `json:"lfs"`
}

// nextLink matches a Link header's rel="next" URL, which the Hub sends
// while a listing has more pages.
var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// Client reads model repositories from a Hub over its HTTP API.
type Client struct {
	// HTTP makes the requests.
	HTTP *http.Client
	// Endpoint is the hub's base URL, e.g. "https://huggingface.co".
	Endpoint string
	// Token, if set, authenticates every request to the hub (see Token).
	Token  string
	Logger *slog.Logger
}

// NewClient returns a Client for the hub at endpoint (see
// resolveEndpoint), authenticated with Token: a purl's for pull, push's
// --remote's for push.
func NewClient(endpoint string, logger *slog.Logger) (Client, error) {
	token, err := Token(endpoint, logger)
	if err != nil {
		return Client{}, err
	}

	client := Client{
		HTTP:     http.DefaultClient,
		Endpoint: resolveEndpoint(endpoint),
		Token:    token,
		Logger:   logger,
	}
	return client, nil
}

// ListFiles returns every file in ref's repository at its commit. Each
// path is checked to stay inside the directory it's written into, since
// the listing comes from the network.
func (c Client) ListFiles(ctx context.Context, ref Ref) ([]File, error) {
	next := fmt.Sprintf("%s/api/models/%s/tree/%s?recursive=true", c.Endpoint, ref.RepoID(), ref.Revision)
	var files []File
	for next != "" {
		response, err := c.get(ctx, http.MethodGet, next)
		if err != nil {
			return nil, err
		}
		var entries []treeEntry
		err = json.NewDecoder(response.Body).Decode(&entries)
		response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s's file list: %w", ref.RepoID(), err)
		}

		for _, entry := range entries {
			if entry.Type != "file" {
				continue
			}
			if !isSafePath(entry.Path) {
				return nil, fmt.Errorf("%s lists a file at %q, outside the repository", ref.RepoID(), entry.Path)
			}
			file := File{
				Path:   entry.Path,
				Size:   entry.Size,
				BlobID: entry.OID,
			}
			if entry.LFS != nil {
				file.SHA256 = entry.LFS.OID
			}
			files = append(files, file)
		}

		next = ""
		if match := nextLink.FindStringSubmatch(response.Header.Get("Link")); match != nil {
			next = match[1]
			// The token goes with every request, so only ever to the hub.
			if !strings.HasPrefix(next, c.Endpoint+"/") {
				return nil, fmt.Errorf("%s's file list continues at %s, outside %s", ref.RepoID(), next, c.Endpoint)
			}
		}
	}
	return files, nil
}

// CheckReadable confirms file can be downloaded, without downloading it:
// a gated or private repository lists its files to anyone, but serves
// them only with a token that has access.
func (c Client) CheckReadable(ctx context.Context, ref Ref, file File) error {
	response, err := c.get(ctx, http.MethodHead, c.fileURL(ref, file))
	if err != nil {
		return err
	}
	response.Body.Close()
	return nil
}

// Download writes file into dir at its path, and fails, removing it, if
// its size or hash isn't what the listing said. A connection that breaks
// partway starts the file over, up to len(retryWaits) times.
func (c Client) Download(ctx context.Context, ref Ref, file File, dir string) error {
	for attempt := 0; ; attempt++ {
		err := c.downloadOnce(ctx, ref, file, dir)
		if err == nil || !isTransient(err) || ctx.Err() != nil || attempt >= len(retryWaits) {
			return err
		}
		wait := jittered(retryWaits[attempt])
		c.Logger.Warn("retrying", "file", file.Path, "attempt", attempt+1, "wait", wait, "error", err)
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// downloadOnce makes one attempt at Download.
func (c Client) downloadOnce(ctx context.Context, ref Ref, file File, dir string) error {
	response, err := c.get(ctx, http.MethodGet, c.fileURL(ref, file))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	path := filepath.Join(dir, filepath.FromSlash(file.Path))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("download %s: %w", file.Path, err)
	}
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("download %s: %w", file.Path, err)
	}

	hasher, want := verifier(file)
	written, err := io.Copy(io.MultiWriter(output, hasher), response.Body)
	if closeErr := output.Close(); err == nil {
		err = closeErr
	}
	if err == nil && written != file.Size {
		err = fmt.Errorf("got %d bytes, want %d", written, file.Size)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); err == nil && got != want {
		err = fmt.Errorf("got content hashing to %s, want %s", got, want)
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("download %s: %w", file.Path, err)
	}
	c.Logger.Info("downloaded", "file", file.Path, "bytes", written)
	return nil
}

// verifier returns the hash that identifies file's content, ready to
// write it to, and the hex digest it must end with.
func verifier(file File) (hash.Hash, string) {
	if file.SHA256 != "" {
		return sha256.New(), file.SHA256
	}
	blob := sha1.New()
	fmt.Fprintf(blob, "blob %d\x00", file.Size)
	return blob, file.BlobID
}

func (c Client) fileURL(ref Ref, file File) string {
	escaped := strings.Split(file.Path, "/")
	for index, segment := range escaped {
		escaped[index] = url.PathEscape(segment)
	}
	return fmt.Sprintf("%s/%s/resolve/%s/%s", c.Endpoint, ref.RepoID(), ref.Revision, strings.Join(escaped, "/"))
}

// keepTokenOnHub is the HTTP client's redirect policy: the token is only
// ever sent to the hub's own host and port. Go's default would also send
// it on to the hub's subdomains (e.g. a CDN), and ignores the port.
func keepTokenOnHub(request *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if request.URL.Host != via[0].URL.Host {
		request.Header.Del("Authorization")
	}
	return nil
}

// call is one HTTP request a Client sends.
type call struct {
	Method string
	URL    string
	// Body, if set, is sent with Size as its length: pre-signed upload
	// URLs refuse a body of unknown length. It's rewound for each retry.
	Body   io.ReadSeeker
	Size   int64
	Header http.Header
}

// retryStatuses are the responses send retries, as huggingface_hub does:
// a timeout, rate limiting, and server errors.
var retryStatuses = []int{
	http.StatusRequestTimeout,
	http.StatusTooManyRequests,
	http.StatusInternalServerError,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
}

// retryWaits are how long send waits before each retry, before jitter,
// unless the server says how long with Retry-After.
var retryWaits = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second}

// maxRetryAfter caps a Retry-After the server asks for.
const maxRetryAfter = time.Minute

// sleep waits for wait, or until ctx is done. Tests replace it.
var sleep = func(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// get sends a body-less request.
func (c Client) get(ctx context.Context, method, target string) (*http.Response, error) {
	request := call{
		Method: method,
		URL:    target,
	}
	return c.send(ctx, request)
}

// send sends request, retrying a network error or a response in
// retryStatuses up to len(retryWaits) times, and returns a *StatusError
// if it was refused. The token goes only to the hub itself, never to a
// URL the hub hands out, such as a pre-signed upload URL; redirects are
// followed, but carry it no further (see keepTokenOnHub).
func (c Client) send(ctx context.Context, request call) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		response, err := c.sendOnce(ctx, request)
		if err == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
			return response, nil
		}

		refusal := err
		retryable := err != nil && ctx.Err() == nil
		wait := jittered(retryWaits[min(attempt, len(retryWaits)-1)])
		if err == nil {
			refusal = hubError(response, request.URL)
			retryable = slices.Contains(retryStatuses, response.StatusCode)
			if seconds, parseErr := strconv.Atoi(response.Header.Get("Retry-After")); parseErr == nil && seconds > 0 {
				wait = min(time.Duration(seconds)*time.Second, maxRetryAfter)
			}
			response.Body.Close()
		}
		if !retryable || attempt >= len(retryWaits) {
			return nil, refusal
		}
		c.Logger.Warn("retrying", "method", request.Method, "url", redact(request.URL), "attempt", attempt+1, "wait", wait, "error", refusal)
		if err := sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// sendOnce makes one attempt at request.
func (c Client) sendOnce(ctx context.Context, request call) (*http.Response, error) {
	var body io.Reader
	if request.Body != nil {
		if _, err := request.Body.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("rewind the body of %s %s: %w", request.Method, redact(request.URL), err)
		}
		body = request.Body
	}
	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, request.URL, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		httpRequest.ContentLength = request.Size
	}
	for name, values := range request.Header {
		httpRequest.Header[name] = values
	}
	if c.Token != "" && c.isHub(httpRequest.URL) {
		httpRequest.Header.Set("Authorization", "Bearer "+c.Token)
	}

	client := *c.HTTP
	client.CheckRedirect = keepTokenOnHub
	return client.Do(httpRequest)
}

// jittered spreads wait by up to a quarter, so clients retrying at once
// don't all come back at once.
func jittered(wait time.Duration) time.Duration {
	return wait + rand.N(wait/4+1)
}

// redact drops target's query, which for a pre-signed URL is its
// signature, so it stays out of errors and logs.
func redact(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	parsed.RawQuery = ""
	return parsed.String()
}

// isTransient reports whether err, while reading a response body, is a
// broken connection worth starting the transfer over for.
func isTransient(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF)
}

// isHub reports whether target is on the hub itself: the same scheme and
// host (and port) as Endpoint.
func (c Client) isHub(target *url.URL) bool {
	hub, err := url.Parse(c.Endpoint)
	return err == nil && target.Scheme == hub.Scheme && target.Host == hub.Host
}

// sendJSON sends payload as request's JSON body, and decodes the response
// into result, unless it's nil. request's Header defaults Content-Type to
// JSON's.
func (c Client) sendJSON(ctx context.Context, request call, payload, result any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if request.Header == nil {
		request.Header = http.Header{}
	}
	if request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Body = bytes.NewReader(data)
	request.Size = int64(len(data))

	response, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if result == nil {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		return fmt.Errorf("parse the response to %s %s: %w", request.Method, request.URL, err)
	}
	return nil
}

// StatusError is a request the server refused, with the Hub's own
// X-Error-Message when it sends one.
type StatusError struct {
	Method, URL string
	StatusCode  int
	Message     string
}

// Error says how to authenticate when the Hub wants a token: it answers
// 401 for a repository that doesn't exist as for one that's private.
func (e *StatusError) Error() string {
	message := fmt.Sprintf("%s %s: %s", e.Method, e.URL, e.Message)
	if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden {
		message += ` (if the repository exists, this needs a token with access to it: set HF_TOKEN, or store one with "bomify login <hub host> --verify=false")`
	}
	return message
}

func hubError(response *http.Response, target string) error {
	message := response.Header.Get("X-Error-Message")
	if message == "" {
		message = response.Status
	}
	statusErr := StatusError{
		Method:     response.Request.Method,
		URL:        redact(target),
		StatusCode: response.StatusCode,
		Message:    message,
	}
	return &statusErr
}

// isSafePath reports whether path, "/"-separated, names a file inside the
// directory it's joined to: relative, with no ".." and no backslashes.
func isSafePath(path string) bool {
	if path == "" || strings.ContainsAny(path, "\\\x00") {
		return false
	}
	return filepath.IsLocal(filepath.FromSlash(path))
}
