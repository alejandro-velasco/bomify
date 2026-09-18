package cmd

import (
	"bytes"
	"testing"
	"time"

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
