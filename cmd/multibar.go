package cmd

import (
	"io"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// newMultiBar creates an mpb container that renders each blob's bar on its
// own line of out, sharing one terminal without clobbering each other's
// output. Callers must call (*mpb.Progress).Wait once every bar returned
// through newProgressFunc has been closed, so the container settles before
// anything else writes to out.
func newMultiBar(out io.Writer) *mpb.Progress {
	return mpb.New(mpb.WithOutput(out))
}

// newProgressFunc returns a transfer.ProgressFunc that renders each blob as
// its own bar under p, shared by every command that transfers OCI blobs
// (pull, push, save, load).
func newProgressFunc(p *mpb.Progress) transfer.ProgressFunc {
	return func(name string, size int64) io.WriteCloser {
		bar := p.AddBar(size,
			mpb.BarWidth(30),
			mpb.PrependDecorators(decor.Name(name)),
			mpb.AppendDecorators(decor.CountersKibiByte("% .2f / % .2f")),
		)
		pw, _ := bar.ProxyWriter(io.Discard)
		return &barWriteCloser{WriteCloser: pw, bar: bar}
	}
}

// barWriteCloser aborts its bar on Close if the blob's transfer ended
// before writing the full size (an error mid-transfer): otherwise that bar
// never reaches a terminal state, and (*mpb.Progress).Wait would hang
// forever waiting for it.
type barWriteCloser struct {
	io.WriteCloser
	bar *mpb.Bar
}

func (w *barWriteCloser) Close() error {
	if !w.bar.AbortedOrCompleted() {
		w.bar.Abort(false)
	}
	return w.WriteCloser.Close()
}
