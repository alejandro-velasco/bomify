package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vbauerster/mpb/v8"
)

func TestProgressFuncCompletesBarOnFullWrite(t *testing.T) {
	mb := newMultiBar(&bytes.Buffer{})
	progress := newProgressFunc(mb)

	w := progress("component", 10)
	if _, err := w.Write(make([]byte, 10)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	waitOrTimeout(t, mb)
}

func TestProgressFuncAbortsBarOnShortWrite(t *testing.T) {
	mb := newMultiBar(&bytes.Buffer{})
	progress := newProgressFunc(mb)

	w := progress("component", 10)
	if _, err := w.Write(make([]byte, 4)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	waitOrTimeout(t, mb)
}

func TestBarLabel(t *testing.T) {
	long := "pkg:generic/" + strings.Repeat("a", 60) + "@1.0"
	for name, want := range map[string]string{
		"pkg:generic/migrate@3.1": "pkg:generic/migrate@3.1",
		"pkg:oci/nginx@1.27.2-debian-12-r1?repository_url=index.docker.io%2Fbitnami%2Fnginx": "pkg:oci/nginx@1.27.2-debian-12-r1",
		"sbom manifest": "sbom manifest",
		long:            long[:maxBarLabel-1] + "…",
		// Cut by characters, never mid-character.
		"pkg:generic/" + strings.Repeat("é", 60): "pkg:generic/" + strings.Repeat("é", maxBarLabel-1-len("pkg:generic/")) + "…",
	} {
		got := barLabel(name)
		if got != want {
			t.Errorf("barLabel(%q) = %q, want %q", name, got, want)
		}
		if n := utf8.RuneCountInString(got); n > maxBarLabel {
			t.Errorf("barLabel(%q) is %d characters, more than %d", name, n, maxBarLabel)
		}
	}
}

// waitOrTimeout fails the test if mb.Wait doesn't return promptly: an
// unclosed or never-completed bar would otherwise hang it forever.
func waitOrTimeout(t *testing.T, mb *mpb.Progress) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		mb.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return after all bars were closed")
	}
}
