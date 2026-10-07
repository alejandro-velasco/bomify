package hub

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testRef() Ref {
	ref := Ref{
		Namespace: "org",
		Name:      "model",
		Revision:  testCommit,
	}
	return ref
}

func TestPull(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{
		Files: testFiles(),
		LFS:   map[string]bool{"model.safetensors": true, "onnx/model.onnx": true},
		Gated: true,
		Token: "hf_secret",
	})
	output := t.TempDir()

	result, err := Pull(context.Background(), fake.client("hf_secret"), testRef(), output, discardLogger())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}

	for path, content := range testFiles() {
		got, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(path)))
		if err != nil || string(got) != content {
			t.Errorf("%s = %q, %v; want %q", path, got, err, content)
		}
	}
	want, _, err := TreeHash(output)
	if err != nil {
		t.Fatal(err)
	}
	if result.Hash.Value != want || result.OutputPath != output {
		t.Errorf("Pull = %+v, want hash %s of %s", result, want, output)
	}
	if len(fake.CDNAuthorization) != 2 || slices.ContainsFunc(fake.CDNAuthorization, func(header string) bool { return header != "" }) {
		t.Errorf("CDN saw Authorization %q, want the token kept on the hub", fake.CDNAuthorization)
	}
}

func TestPullFailsOnCorruptFile(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{
		Files:   testFiles(),
		Corrupt: "tokenizer/vocab.json",
	})

	_, err := Pull(context.Background(), fake.client(""), testRef(), t.TempDir(), discardLogger())
	if err == nil || !strings.Contains(err.Error(), "tokenizer/vocab.json") {
		t.Errorf("Pull = %v, want the corrupt file named", err)
	}
}

func TestCheckPull(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{Files: testFiles()})

	result, err := CheckPull(context.Background(), fake.client(""), testRef())
	if err != nil {
		t.Fatalf("CheckPull: %v", err)
	}
	if want := "huggingface.co/org/model@" + testCommit; result.OutputPath != want || result.Hash.Value != "" {
		t.Errorf("CheckPull = %+v, want %s and no hash", result, want)
	}
}

func TestCheckPullReportsHubErrors(t *testing.T) {
	fake := startFakeHub(t, &fakeHub{
		Files: testFiles(),
		Gated: true,
		Token: "hf_secret",
	})

	missing := testRef()
	missing.Revision = strings.Repeat("0", 40)
	if _, err := CheckPull(context.Background(), fake.client(""), missing); err == nil || !strings.Contains(err.Error(), "Invalid rev id") {
		t.Errorf("CheckPull(missing commit) = %v, want the Hub's message", err)
	}

	// A gated repository lists its files to anyone, so only asking for
	// one shows a token is needed.
	_, err := CheckPull(context.Background(), fake.client(""), testRef())
	if err == nil || !strings.Contains(err.Error(), "restricted") || !strings.Contains(err.Error(), "HF_TOKEN") {
		t.Errorf("CheckPull(gated, no token) = %v, want the Hub's message and how to authenticate", err)
	}
}

func TestPullRetriesBrokenDownload(t *testing.T) {
	waits := noSleep(t)
	fake := startFakeHub(t, &fakeHub{
		Files:     testFiles(),
		LFS:       map[string]bool{"model.safetensors": true},
		BreakOnce: map[string]bool{"config.json": true, "model.safetensors": true},
	})
	output := t.TempDir()

	if _, err := Pull(context.Background(), fake.client(""), testRef(), output, discardLogger()); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	for path, content := range testFiles() {
		if got := readTestFile(t, output, path); got != content {
			t.Errorf("%s = %q, want %q", path, got, content)
		}
	}
	if len(*waits) != 2 {
		t.Errorf("retried %d times, want once per broken file", len(*waits))
	}
}
