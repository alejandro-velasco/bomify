package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/alejandro-velasco/bomify/pkg/auth"
	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// setAuth adds HTTP Basic auth to req from bomify's shared credential
// store (see pkg/auth), if any credentials are stored for req's host. A
// host with nothing stored is left as an anonymous request.
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
// outputDir as ref.Filename(), reporting its progress to progress.
func Pull(ref Ref, outputDir string, logger *slog.Logger, progress *plugin.Progress) (*plugin.Result, error) {
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
	// ContentLength is -1 when the server doesn't say.
	reported := progress.Writer(ref.Filename(), max(resp.ContentLength, 0))
	defer reported.Close()
	if _, err := io.Copy(io.MultiWriter(f, hasher, reported), resp.Body); err != nil {
		return nil, fmt.Errorf("save %s: %w", path, err)
	}
	logger.Info("saved", "path", path)

	return &plugin.Result{
		OutputPath: path,
		Message:    fmt.Sprintf("pulled %s", ref.DownloadURL),
		Hash:       plugin.NewHash(hex.EncodeToString(hasher.Sum(nil))),
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
