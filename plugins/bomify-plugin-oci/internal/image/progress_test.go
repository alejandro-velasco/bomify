package image

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/random"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

func TestPullReportsEachLayer(t *testing.T) {
	host := newTestRegistry(t)
	ref := host + "/test/progress-image:1.0"

	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	if err := crane.Push(img, ref); err != nil {
		t.Fatalf("seed registry with crane.Push: %v", err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}

	progressFile := filepath.Join(t.TempDir(), "progress")
	progress, closeProgress, err := plugin.OpenProgress(progressFile)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProgress()

	if _, err := Pull(ref, t.TempDir(), testLogger(), progress); err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	// The last event for each part is where it ended.
	last := map[string]plugin.ProgressEvent{}
	file, err := os.Open(progressFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event plugin.ProgressEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("line %q: %v", scanner.Text(), err)
		}
		last[event.Name] = event
	}

	for _, layer := range layers {
		digest, err := layer.Digest()
		if err != nil {
			t.Fatal(err)
		}
		size, err := layer.Size()
		if err != nil {
			t.Fatal(err)
		}
		name := shortDigest(digest.String())
		want := plugin.ProgressEvent{Name: name, Current: size, Total: size}
		if last[name] != want {
			t.Errorf("layer %s ended at %+v, want %+v", name, last[name], want)
		}
	}
}

func TestBlobDigest(t *testing.T) {
	const digest = "sha256:25f1d6b1951ac8eb3740558fe94cb83d377bdadf95fd9f98b50d2e1b96130471"
	blob := &http.Request{URL: &url.URL{Path: "/v2/team/app/blobs/" + digest}}
	// Docker Hub's CDN has a "/blobs/" of its own, but no digest after it.
	redirected := &http.Request{
		URL:      &url.URL{Host: "production.cloudflare.docker.com", Path: "/registry-v2/docker/registry/v2/blobs/sha256/25/25f1d6b1951ac8eb3740558fe94cb83d377bdadf95fd9f98b50d2e1b96130471/data"},
		Response: &http.Response{Request: blob},
	}
	manifest := &http.Request{URL: &url.URL{Path: "/v2/team/app/manifests/1.0"}}
	// A repository may be named with a "blobs" of its own.
	blobsRepository := &http.Request{URL: &url.URL{Path: "/v2/team/blobs/app/manifests/1.0"}}

	for _, test := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{name: "a blob", req: blob, want: digest},
		{name: "a blob's redirect", req: redirected, want: digest},
		{name: "a manifest", req: manifest, want: ""},
		{name: "a manifest in a repository named blobs", req: blobsRepository, want: ""},
	} {
		if got := blobDigest(test.req); got != test.want {
			t.Errorf("%s: blobDigest = %q, want %q", test.name, got, test.want)
		}
	}
}
