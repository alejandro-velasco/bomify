package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/pkg/auth"
	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// setAuth adds HTTP Basic auth to req from bomify's shared credential
// store (fetched via pkg/auth.Get; see internal/auth for the store
// itself, the same one `bomify login`/`docker login` write), if any
// credentials are stored for req's host. A host with nothing stored is
// left as an anonymous request.
func setAuth(req *http.Request) error {
	host := req.URL.Host
	if host == "" {
		return nil
	}

	username, password, err := auth.Get(host)
	if err != nil {
		return fmt.Errorf("look up credentials for %s: %w", host, err)
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}

	return nil
}

// Pull downloads ref.DownloadURL with a plain HTTP GET and saves it into
// outputDir as ref.Filename().
func Pull(ref Ref, outputDir string, hashAlgorithm cdx.HashAlgorithm, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("GET", "url", ref.DownloadURL)
	req, err := http.NewRequest(http.MethodGet, ref.DownloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build GET request for %s: %w", ref.DownloadURL, err)
	}
	if err := setAuth(req); err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", ref.DownloadURL, err)
	}
	defer resp.Body.Close()
	logger.Info("response received", "status", resp.Status)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GET %s: unexpected status %s: %s", ref.DownloadURL, resp.Status, strings.TrimSpace(string(body)))
	}

	path := filepath.Join(outputDir, ref.Filename())
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, hasher), resp.Body); err != nil {
		return nil, fmt.Errorf("save %s: %w", path, err)
	}
	logger.Info("saved", "path", path)

	digest, err := digestHash(hashAlgorithm, hasher)
	if err != nil {
		return nil, err
	}

	return &plugin.Result{
		OutputPath: path,
		Message:    fmt.Sprintf("pulled %s", ref.DownloadURL),
		Hash:       digest,
	}, nil
}

// CheckPull verifies ref.DownloadURL exists and is fetchable with a
// plain HTTP HEAD instead of downloading it. No hash is reported: a HEAD
// response carries no content to hash.
func CheckPull(ref Ref, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("HEAD", "url", ref.DownloadURL)
	req, err := http.NewRequest(http.MethodHead, ref.DownloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build HEAD request for %s: %w", ref.DownloadURL, err)
	}
	if err := setAuth(req); err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HEAD %s: %w", ref.DownloadURL, err)
	}
	defer resp.Body.Close()
	logger.Info("response received", "status", resp.Status)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HEAD %s: unexpected status %s", ref.DownloadURL, resp.Status)
	}

	return &plugin.Result{OutputPath: ref.DownloadURL, Message: fmt.Sprintf("%s exists and is pullable", ref.DownloadURL)}, nil
}

// Push uploads the artifact a prior Pull wrote into inputDir to remote
// with a plain HTTP PUT. remote is used exactly as given, with nothing
// appended: it's expected to already be the full destination URL (e.g. a
// presigned upload URL), matching how a simple PUT-based artifact store
// works.
func Push(inputDir string, ref Ref, remote string, logger *slog.Logger) (*plugin.Result, error) {
	path := filepath.Join(inputDir, ref.Filename())

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	req, err := http.NewRequest(http.MethodPut, remote, f)
	if err != nil {
		return nil, fmt.Errorf("build PUT request for %s: %w", remote, err)
	}
	req.ContentLength = info.Size()
	if err := setAuth(req); err != nil {
		return nil, err
	}

	logger.Info("PUT", "url", remote, "size", info.Size())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", remote, err)
	}
	defer resp.Body.Close()
	logger.Info("response received", "status", resp.Status)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("PUT %s: unexpected status %s: %s", remote, resp.Status, strings.TrimSpace(string(body)))
	}

	return &plugin.Result{OutputPath: remote, Message: fmt.Sprintf("pushed %s to %s", path, remote)}, nil
}

// CheckPush is a best-effort check, unlike CheckPull: it never falls
// back to a real PUT, since remote is often a single-use presigned URL
// a "check" must not consume. Only a plain HEAD is tried; a clear
// auth rejection (401/403) fails, anything else (including a HEAD
// remote doesn't support, or a 404 — normal for a push target) is
// reported as success with a message noting write permission wasn't
// actually verified.
func CheckPush(remote string, logger *slog.Logger) (*plugin.Result, error) {
	logger.Info("HEAD", "url", remote)
	req, err := http.NewRequest(http.MethodHead, remote, nil)
	if err != nil {
		return nil, fmt.Errorf("build HEAD request for %s: %w", remote, err)
	}
	if err := setAuth(req); err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// remote is unreachable, not merely unwritable — that's the one
		// case worth failing on, even for a best-effort check.
		return nil, fmt.Errorf("HEAD %s: %w", remote, err)
	}
	defer resp.Body.Close()
	logger.Info("response received", "status", resp.Status)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HEAD %s: unexpected status %s", remote, resp.Status)
	}

	return &plugin.Result{
		OutputPath: remote,
		Message:    fmt.Sprintf("%s is reachable; write permission not verified (HEAD is not authoritative for a PUT URL)", remote),
	}, nil
}

func digestHash(hashAlgorithm cdx.HashAlgorithm, hasher hash.Hash) (plugin.Hash, error) {
	if hashAlgorithm != cdx.HashAlgoSHA256 {
		return plugin.Hash{}, fmt.Errorf("bomify-plugin-generic: unsupported hash algorithm %q, only %s is supported", hashAlgorithm, cdx.HashAlgoSHA256)
	}

	return plugin.Hash{Algorithm: cdx.HashAlgoSHA256, Value: hex.EncodeToString(hasher.Sum(nil))}, nil
}
