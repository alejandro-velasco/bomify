package cmd

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestMultiBarReserveAssignsSequentialLines(t *testing.T) {
	mb := newMultiBar(&bytes.Buffer{})

	const n = 20
	lines := make(chan int, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := mb.reserve().(*barLineWriter)
			lines <- w.line
		}()
	}
	wg.Wait()
	close(lines)

	seen := make(map[int]bool)
	for line := range lines {
		if seen[line] {
			t.Fatalf("line %d reserved twice", line)
		}
		seen[line] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct lines, want %d", len(seen), n)
	}
	if mb.lines != n {
		t.Errorf("mb.lines = %d, want %d", mb.lines, n)
	}
}

func TestBarLineWriterRepositionsCursor(t *testing.T) {
	var buf bytes.Buffer
	mb := newMultiBar(&buf)

	top := mb.reserve()    // line 0
	_ = mb.reserve()        // line 1
	bottom := mb.reserve() // line 2

	buf.Reset() // discard the reservation newlines; only inspect redraws below

	if _, err := fmt.Fprint(top, "top-content"); err != nil {
		t.Fatalf("write to top line: %v", err)
	}
	got := buf.String()
	want := "\x1b[2A\r\x1b[2Ktop-content\x1b[2B\r"
	if got != want {
		t.Errorf("top line write = %q, want %q", got, want)
	}

	buf.Reset()
	if _, err := fmt.Fprint(bottom, "bottom-content"); err != nil {
		t.Fatalf("write to bottom line: %v", err)
	}
	got = buf.String()
	want = "\r\x1b[2Kbottom-content\r"
	if got != want {
		t.Errorf("bottom line write = %q, want %q", got, want)
	}
}
