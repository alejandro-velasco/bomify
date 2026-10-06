package cmd

import (
	"io"
	"strings"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/alejandro-velasco/bomify/internal/logging"
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

// logAboveBars sends bomify's log lines through p, which prints them
// above its bars rather than through them (see logging.SetOutput), and
// returns the function that stops it. It does so only when out, where p
// draws, is a terminal: elsewhere p draws no bars, and never flushes what's
// written to it, so log lines go straight to stderr as usual.
func logAboveBars(p *mpb.Progress, out io.Writer) (restore func()) {
	if !logging.IsTerminal(out) {
		return func() {}
	}
	return logging.SetOutput(p)
}

// maxBarLabel is the most characters of a blob's label a bar shows (see
// barLabel), so a long one can't push every bar off a normal terminal.
const maxBarLabel = 50

// newProgressFunc returns a transfer.ProgressFunc that renders each blob as
// its own bar under p, shared by every command that transfers OCI blobs
// (pull, push, save, load). Labels and counters are each padded to their
// column's widest, so every bar starts and ends in the same place.
func newProgressFunc(p *mpb.Progress) transfer.ProgressFunc {
	return func(name string, size int64) io.WriteCloser {
		label := decor.Name(barLabel(name), decor.WCSyncSpaceR)
		current := decor.Current(decor.SizeB1024(0), "% .2f", decor.WCSyncSpace)
		total := decor.Total(decor.SizeB1024(0), "% .2f", decor.WCSyncSpace)
		bar := p.AddBar(size,
			mpb.BarWidth(30),
			mpb.PrependDecorators(label),
			mpb.AppendDecorators(current, decor.Name(" /"), total),
		)
		pw, _ := bar.ProxyWriter(io.Discard)
		return &barWriteCloser{WriteCloser: pw, bar: bar}
	}
}

// barLabel is how a bar shows a blob's label, usually a purl: without its
// qualifiers (from "?"), which are long and rarely tell components apart,
// and cut to maxBarLabel characters, ending in "…", if still longer.
// Errors keep the full label.
func barLabel(name string) string {
	label, _, _ := strings.Cut(name, "?")
	runes := []rune(label)
	if len(runes) <= maxBarLabel {
		return label
	}
	return string(runes[:maxBarLabel-1]) + "…"
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
