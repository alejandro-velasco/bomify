package image

import (
	"io"
	"net/http"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// progressTransport reports each blob it downloads, such as a layer, to
// progress as it's read, named by its short digest (see shortDigest).
type progressTransport struct {
	base     http.RoundTripper
	progress *plugin.Progress
}

// withProgress is the transport crane downloads through: remote's
// default, reporting each blob to progress.
func withProgress(progress *plugin.Progress) http.RoundTripper {
	transport := progressTransport{
		base:     remote.DefaultTransport,
		progress: progress,
	}
	return transport
}

func (t progressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || req.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return resp, err
	}

	digest := blobDigest(req)
	if digest == "" {
		return resp, nil
	}
	// ContentLength is -1 when the registry doesn't say.
	reported := t.progress.Writer(shortDigest(digest), max(resp.ContentLength, 0))
	resp.Body = &progressBody{
		ReadCloser: resp.Body,
		reported:   reported,
	}
	return resp, nil
}

// blobDigest is the digest of the blob req downloads, from its URL,
// "/v2/<name>/blobs/<digest>", or that of the request that redirected to
// it, as a registry may to a CDN; "" if it downloads no blob.
func blobDigest(req *http.Request) string {
	for req != nil {
		dir, digest := path.Split(req.URL.Path)
		if path.Base(dir) == "blobs" {
			if _, err := v1.NewHash(digest); err == nil {
				return digest
			}
		}
		if req.Response == nil {
			return ""
		}
		req = req.Response.Request
	}
	return ""
}

// shortDigest is digest's first 12 hex characters, as bomify labels a
// blob.
func shortDigest(digest string) string {
	_, hex, _ := strings.Cut(digest, ":")
	return hex[:min(len(hex), 12)]
}

// progressBody reports what's read from a response body to reported,
// closing it with the body.
type progressBody struct {
	io.ReadCloser
	reported io.WriteCloser
}

func (b *progressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.reported.Write(p[:n])
	return n, err
}

func (b *progressBody) Close() error {
	b.reported.Close()
	return b.ReadCloser.Close()
}
