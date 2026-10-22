package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ProgressEvent is one line of a pull's --progress file: how much of one
// part of the component, such as a file or a layer, has been pulled (see
// plugins/contracts/component/v1/CONTRACT.md).
type ProgressEvent struct {
	// Name is the part, which bomify shows as a bar of its own.
	Name string `json:"name"`
	// Current is how many of its bytes have been pulled so far.
	Current int64 `json:"current"`
	// Total is its size in bytes, or 0 if unknown.
	Total int64 `json:"total,omitempty"`
}

// progressInterval is how often a Progress.Writer reports, at most.
const progressInterval = 100 * time.Millisecond

// Progress appends a pull's ProgressEvents to its --progress file. Its
// methods are safe for concurrent use, and a nil *Progress reports
// nothing, so a plugin can report unconditionally.
type Progress struct {
	mu   sync.Mutex
	file *os.File
}

// OpenProgress opens path, the file a pull's --progress flag names, for
// appending, and returns a close func the caller should defer. An empty
// path gives a nil Progress.
func OpenProgress(path string) (*Progress, func() error, error) {
	if path == "" {
		return nil, func() error { return nil }, nil
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open progress file %s: %w", path, err)
	}
	return &Progress{file: file}, file.Close, nil
}

// Report appends one event: current of name's total bytes (0 if unknown)
// pulled so far. Progress is only shown, so a failed write is ignored
// rather than failing the pull.
func (p *Progress) Report(name string, current, total int64) {
	if p == nil {
		return
	}

	event := ProgressEvent{
		Name:    name,
		Current: current,
		Total:   total,
	}
	line, err := json.Marshal(event)
	if err != nil {
		return
	}

	// One write per line, so lines from concurrent parts never interleave.
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = p.file.Write(append(line, '\n'))
}

// Writer returns a writer that reports the bytes written to it as name's
// progress, of total (0 if unknown): write what's pulled through it, with
// io.MultiWriter or io.TeeReader, and Close it once done. It reports at
// once, then at most every progressInterval, and on Close. Unlike p, it's
// for one goroutine.
func (p *Progress) Writer(name string, total int64) io.WriteCloser {
	writer := &progressWriter{
		progress: p,
		name:     name,
		total:    total,
		reported: time.Now(),
	}
	p.Report(name, 0, total)
	return writer
}

// progressWriter is what Progress.Writer returns.
type progressWriter struct {
	progress *Progress
	name     string
	total    int64
	current  int64
	reported time.Time
}

func (w *progressWriter) Write(b []byte) (int, error) {
	w.current += int64(len(b))
	if time.Since(w.reported) >= progressInterval {
		w.progress.Report(w.name, w.current, w.total)
		w.reported = time.Now()
	}
	return len(b), nil
}

func (w *progressWriter) Close() error {
	w.progress.Report(w.name, w.current, w.total)
	return nil
}
