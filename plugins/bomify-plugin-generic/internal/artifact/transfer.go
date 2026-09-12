package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"bomify/internal/auth"
	"bomify/internal/plugin"
)

// setAuth adds HTTP Basic auth to req from bomify's shared credential
// store (see internal/auth — the same store `bomify login`/`docker
// login` write), if any credentials are stored for req's host. A host
// with nothing stored is left as an anonymous request.
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
func Pull(ref Ref, outputDir string, hashAlgorithm cdx.HashAlgorithm) (*plugin.Result, error) {
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

// Push uploads the artifact a prior Pull wrote into inputDir to remote
// with a plain HTTP PUT. remote is used exactly as given, with nothing
// appended: it's expected to already be the full destination URL (e.g. a
// presigned upload URL), matching how a simple PUT-based artifact store
// works.
func Push(inputDir string, ref Ref, remote string) (*plugin.Result, error) {
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", remote, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("PUT %s: unexpected status %s: %s", remote, resp.Status, strings.TrimSpace(string(body)))
	}

	return &plugin.Result{OutputPath: remote, Message: fmt.Sprintf("pushed %s to %s", path, remote)}, nil
}

func digestHash(hashAlgorithm cdx.HashAlgorithm, hasher hash.Hash) (plugin.Hash, error) {
	if hashAlgorithm != cdx.HashAlgoSHA256 {
		return plugin.Hash{}, fmt.Errorf("bomify-plugin-generic: unsupported hash algorithm %q, only %s is supported", hashAlgorithm, cdx.HashAlgoSHA256)
	}

	return plugin.Hash{Algorithm: cdx.HashAlgoSHA256, Value: hex.EncodeToString(hasher.Sum(nil))}, nil
}
