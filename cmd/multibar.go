package cmd

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"

	"bomify/internal/ocitransfer"
)

// multiBar lets several progressbar.ProgressBar instances, each redrawing
// concurrently from its own goroutine, share one terminal without
// clobbering each other's output: unlike mpb, schollz/progressbar has no
// notion of a shared container, so every bar just writes "\r<content>" to
// whatever io.Writer it's given, assuming it owns the whole terminal. Giving
// each bar a writer from multiBar instead makes every redraw first move the
// cursor up to that bar's own reserved line, clear it, write, then move
// back down, so redraws never collide with a different bar's line.
//
// This relies on ANSI cursor-movement escapes, which modern terminals
// (Windows Terminal, VS Code's integrated terminal, any VT100-ish
// Unix terminal) support; a terminal without ANSI support will see the
// raw escape codes instead of clean output.
type multiBar struct {
	mu    sync.Mutex
	out   io.Writer
	lines int
}

func newMultiBar(out io.Writer) *multiBar {
	return &multiBar{out: out}
}

// reserve allocates the next terminal line for a new bar, returning a
// writer that redraws only that line.
func (m *multiBar) reserve() io.Writer {
	m.mu.Lock()
	defer m.mu.Unlock()

	line := m.lines
	m.lines++
	fmt.Fprintln(m.out)

	return &barLineWriter{m: m, line: line}
}

type barLineWriter struct {
	m    *multiBar
	line int
}

func (w *barLineWriter) Write(p []byte) (int, error) {
	w.m.mu.Lock()
	defer w.m.mu.Unlock()

	up := w.m.lines - 1 - w.line
	if up > 0 {
		fmt.Fprintf(w.m.out, "\x1b[%dA", up)
	}
	fmt.Fprint(w.m.out, "\r\x1b[2K")

	n, err := w.m.out.Write(p)

	if up > 0 {
		fmt.Fprintf(w.m.out, "\x1b[%dB", up)
	}
	fmt.Fprint(w.m.out, "\r")

	return n, err
}

// newProgressFunc returns an ocitransfer.ProgressFunc that renders each
// blob as its own bar via mb, shared by every command that transfers OCI
// blobs (pull, push, save, load).
func newProgressFunc(mb *multiBar) ocitransfer.ProgressFunc {
	return func(name string, size int64) io.WriteCloser {
		// Deliberately no OptionClearOnFinish: without OptionUseANSICodes
		// too, progressbar's finish path is a no-op, so a blob small or
		// fast enough to complete within a single write would render
		// nothing at all — no bar, ever. Leaving the completed bar in
		// place (like a finished `docker pull` layer line) guarantees at
		// least one real render for every blob, regardless of its size.
		return progressbar.NewOptions64(size,
			progressbar.OptionSetWriter(mb.reserve()),
			progressbar.OptionSetDescription(name),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(65*time.Millisecond),
		)
	}
}
