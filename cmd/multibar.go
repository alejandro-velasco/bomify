package cmd

import (
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
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

// startBars starts bars drawn on out, with bomify's log lines printed
// above them meanwhile (see logAboveBars). Call settle once every bar has
// ended, before anything else is written: it waits until the bars are
// drawn in their final state, then sends log lines back to stderr, as
// written while bars are on screen they'd tear through them. A bar that
// never ends makes settle hang.
func startBars(out io.Writer) (bars *mpb.Progress, settle func()) {
	bars = newMultiBar(out)
	restoreLogs := logAboveBars(bars, out)
	settle = func() {
		bars.Wait()
		restoreLogs()
	}
	return bars, settle
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
		bar := addSizeBar(p, name, size)
		pw, _ := bar.ProxyWriter(io.Discard)
		return &barWriteCloser{WriteCloser: pw, bar: bar}
	}
}

// addSizeBar adds a bar under p for size bytes of name, or an unknown
// number if size is 0, which completes only once its total is set.
func addSizeBar(p *mpb.Progress, name string, size int64) *mpb.Bar {
	label := decor.Name(barLabel(name), decor.WCSyncSpaceR)
	current := decor.Current(decor.SizeB1024(0), "% .2f", decor.WCSyncSpace)
	total := decor.Total(decor.SizeB1024(0), "% .2f", decor.WCSyncSpace)
	return p.AddBar(size,
		mpb.BarWidth(30),
		mpb.PrependDecorators(label),
		mpb.AppendDecorators(current, decor.Name(" /"), total),
	)
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

// pluginTracker shows each plugin pull under p (see plugin.Tracker): a
// spinner while the plugin reports no progress, then a bar for each part
// it reports, as a blob's.
type pluginTracker struct {
	progress *mpb.Progress
}

func (t pluginTracker) Start(label string) plugin.Pulling {
	pull := &pluginPull{
		progress: t.progress,
		label:    label,
		parts:    map[string]*pluginPart{},
	}
	// A total of 0 keeps the spinner going until Done ends it, and a width
	// of 1 shows one spinning character rather than a bar's width of them.
	pull.spinner = t.progress.New(0, mpb.SpinnerStyle(),
		mpb.BarWidth(1),
		mpb.PrependDecorators(decor.Name(barLabel(label), decor.WCSyncSpaceR)),
		mpb.BarFillerMiddleware(func(spinner mpb.BarFiller) mpb.BarFiller {
			return spinnerFiller(spinner, &pull.failed)
		}),
	)
	return pull
}

// spinnerFiller shows spinner until its pull ends, then how it ended:
// "done", or "failed" if failed is set. A spinner is only aborted to drop
// it for the pull's bars, and shows nothing on its way out.
func spinnerFiller(spinner mpb.BarFiller, failed *atomic.Bool) mpb.BarFiller {
	return mpb.BarFillerFunc(func(w io.Writer, stat decor.Statistics) error {
		if stat.Aborted {
			return nil
		}
		if !stat.Completed {
			return spinner.Fill(w, stat)
		}
		outcome := "done"
		if failed.Load() {
			outcome = "failed"
		}
		_, err := io.WriteString(w, outcome)
		return err
	})
}

// pluginPull is one pull a pluginTracker shows.
type pluginPull struct {
	progress *mpb.Progress
	label    string
	spinner  *mpb.Bar
	// failed is whether the pull failed, which the spinner shows if the
	// plugin reported no parts. The spinner reads it as it's drawn.
	failed atomic.Bool

	mu    sync.Mutex
	parts map[string]*pluginPart
}

// pluginPart is the bar of one part a plugin reports, and the total it
// has, 0 until one is reported.
type pluginPart struct {
	bar   *mpb.Bar
	total int64
}

// Update shows event on its part's bar, replacing the spinner with the
// first: from then on, the parts' bars show the pull.
func (p *pluginPull) Update(event pluginlib.ProgressEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()

	part, ok := p.parts[event.Name]
	if !ok {
		if len(p.parts) == 0 {
			// Dropped, not just ended, so it leaves no line behind.
			p.spinner.Abort(true)
		}
		bar := addSizeBar(p.progress, event.Name+" "+p.label, event.Total)
		part = &pluginPart{
			bar:   bar,
			total: event.Total,
		}
		p.parts[event.Name] = part
	} else if event.Total > 0 && event.Total != part.total {
		// The plugin learned the part's size after its first event, or it
		// changed. SetTotal alone only shows the new total: a bar created
		// with none doesn't complete until EnableTriggerComplete says to,
		// once current reaches it.
		part.bar.SetTotal(event.Total, false)
		part.bar.EnableTriggerComplete()
		part.total = event.Total
	}
	part.bar.SetCurrent(event.Current)
}

// Done completes the pull's bars, at whatever each reached, or aborts
// them if it failed. Its spinner, if the plugin reported no parts, ends
// either way, showing which (see spinnerFiller).
func (p *pluginPull) Done(ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.parts) == 0 {
		p.failed.Store(!ok)
		p.spinner.SetTotal(-1, true)
		return
	}
	for _, part := range p.parts {
		finishBar(part.bar, ok)
	}
}

// finishBar completes bar at whatever count it reached, which a part left
// short or of unknown size never otherwise does, or, if !ok, aborts it,
// leaving it on screen. A bar already finished ignores both. Every bar
// must end one way or the other, or (*mpb.Progress).Wait hangs.
func finishBar(bar *mpb.Bar, ok bool) {
	if !ok {
		bar.Abort(false)
		return
	}
	// A negative total means "the current count".
	bar.SetTotal(-1, true)
}
