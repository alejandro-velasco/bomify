package image

import (
	"io"
	"log"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestRegistry starts an in-process OCI registry — a real implementation
// of the distribution API (github.com/google/go-containerregistry's own
// test registry), not a mock of crane or of Pull/Push — and returns its
// host:port. go-containerregistry treats "127.0.0.1:<port>" (and
// "localhost:<port>") as plain HTTP automatically, so no extra crane
// options are needed to talk to it.
func newTestRegistry(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "http://")
}

func TestPull(t *testing.T) {
	host := newTestRegistry(t)
	ref := host + "/test/pull-image:1.0"

	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	if err := crane.Push(img, ref); err != nil {
		t.Fatalf("seed registry with crane.Push: %v", err)
	}
	wantDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("img.Digest: %v", err)
	}

	outputDir := t.TempDir()
	result, err := Pull(ref, outputDir, cdx.HashAlgoSHA256, testLogger())
	if err != nil {
		t.Fatalf("Pull() error = %v", err)
	}

	if result.OutputPath != outputDir {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, outputDir)
	}
	if result.Hash.Algorithm != cdx.HashAlgoSHA256 {
		t.Errorf("Hash.Algorithm = %q, want %q", result.Hash.Algorithm, cdx.HashAlgoSHA256)
	}
	if result.Hash.Value != wantDigest.Hex {
		t.Errorf("Hash.Value = %q, want %q", result.Hash.Value, wantDigest.Hex)
	}

	// The OCI layout Pull wrote must actually be valid and loadable, not
	// just "some files landed in outputDir".
	idx, err := layout.ImageIndexFromPath(outputDir)
	if err != nil {
		t.Fatalf("read OCI layout Pull wrote: %v", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("read OCI layout manifest: %v", err)
	}
	if len(manifest.Manifests) == 0 {
		t.Fatal("OCI layout Pull wrote has no images in it")
	}
}

func TestPullUnsupportedHashAlgorithm(t *testing.T) {
	host := newTestRegistry(t)
	ref := host + "/test/pull-image:1.0"

	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	if err := crane.Push(img, ref); err != nil {
		t.Fatalf("seed registry with crane.Push: %v", err)
	}

	if _, err := Pull(ref, t.TempDir(), cdx.HashAlgoMD5, testLogger()); err == nil {
		t.Fatal("Pull() with an unsupported hash algorithm: expected error, got nil")
	}
}

func TestPullMissingImage(t *testing.T) {
	host := newTestRegistry(t)
	ref := host + "/test/does-not-exist:1.0"

	if _, err := Pull(ref, t.TempDir(), cdx.HashAlgoSHA256, testLogger()); err == nil {
		t.Fatal("Pull() for an image never pushed: expected error, got nil")
	}
}

func TestPush(t *testing.T) {
	host := newTestRegistry(t)

	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	wantDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("img.Digest: %v", err)
	}

	inputDir := t.TempDir()
	if err := crane.SaveOCI(img, inputDir); err != nil {
		t.Fatalf("crane.SaveOCI (seed local layout): %v", err)
	}

	remote := host + "/test"
	result, err := Push(inputDir, "pkg:oci/push-image@2.0", remote, testLogger())
	if err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	wantDst := host + "/test/push-image:2.0"
	if result.OutputPath != wantDst {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, wantDst)
	}

	// Round-trip: what Push published must actually be pullable, with the
	// same digest as what was pushed — not just "Push returned no error".
	pulled, err := crane.Pull(wantDst)
	if err != nil {
		t.Fatalf("crane.Pull(%q) after Push: %v", wantDst, err)
	}
	gotDigest, err := pulled.Digest()
	if err != nil {
		t.Fatalf("pulled.Digest: %v", err)
	}
	if gotDigest != wantDigest {
		t.Errorf("pulled digest = %s, want %s", gotDigest, wantDigest)
	}
}

func TestPushInvalidPurl(t *testing.T) {
	host := newTestRegistry(t)

	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	inputDir := t.TempDir()
	if err := crane.SaveOCI(img, inputDir); err != nil {
		t.Fatalf("crane.SaveOCI: %v", err)
	}

	if _, err := Push(inputDir, "not-a-purl", host+"/test", testLogger()); err == nil {
		t.Fatal("Push() with an unparseable purl: expected error, got nil")
	}
}

func TestPushWithoutLocalLayout(t *testing.T) {
	host := newTestRegistry(t)

	if _, err := Push(t.TempDir(), "pkg:oci/push-image@2.0", host+"/test", testLogger()); err == nil {
		t.Fatal("Push() with no OCI layout in --input: expected error, got nil")
	}
}
