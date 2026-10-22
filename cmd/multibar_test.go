package cmd

import (
	"bytes"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/alejandro-velasco/bomify/internal/logging"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
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
		"sbom": "sbom",
		long:   long[:maxBarLabel-1] + "…",
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

// TestPluginTrackerSettlesEveryBar covers each way a plugin pull can go:
// whichever it is, its spinner or bars must end, or Wait hangs.
func TestPluginTrackerSettlesEveryBar(t *testing.T) {
	for _, test := range []struct {
		name   string
		events []pluginlib.ProgressEvent
		ok     bool
	}{
		{name: "no progress reported", ok: true},
		{name: "no progress reported, failed", ok: false},
		{name: "a part pulled in full", events: []pluginlib.ProgressEvent{{Name: "a", Total: 4}, {Name: "a", Current: 4, Total: 4}}, ok: true},
		{name: "parts left short", events: []pluginlib.ProgressEvent{{Name: "a", Current: 1, Total: 4}, {Name: "b", Current: 2}}, ok: true},
		{name: "a total reported late", events: []pluginlib.ProgressEvent{{Name: "a", Current: 1}, {Name: "a", Current: 2, Total: 8}}, ok: true},
		{name: "parts left short, failed", events: []pluginlib.ProgressEvent{{Name: "a", Current: 1, Total: 4}, {Name: "b", Current: 2}}, ok: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mb := newMultiBar(&bytes.Buffer{})
			tracker := pluginTracker{progress: mb}

			pulling := tracker.Start("pkg:oci/nginx@1.27")
			for _, event := range test.events {
				pulling.Update(event)
			}
			pulling.Done(test.ok)

			waitOrTimeout(t, mb)
		})
	}
}

// TestSpinnerFillerShowsHowAPullEnded covers the spinner's last word,
// including a spinner dropped for the bars of parts a plugin reported,
// which must not show as failed on its way out.
func TestSpinnerFillerShowsHowAPullEnded(t *testing.T) {
	spinning := mpb.BarFillerFunc(func(w io.Writer, _ decor.Statistics) error {
		_, err := io.WriteString(w, "spinning")
		return err
	})
	for _, test := range []struct {
		name   string
		stat   decor.Statistics
		failed bool
		want   string
	}{
		{name: "pulling", want: "spinning"},
		{name: "done", stat: decor.Statistics{Completed: true}, want: "done"},
		{name: "failed", stat: decor.Statistics{Completed: true}, failed: true, want: "failed"},
		{name: "dropped for parts' bars", stat: decor.Statistics{Aborted: true}, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var failed atomic.Bool
			failed.Store(test.failed)
			var out bytes.Buffer

			if err := spinnerFiller(spinning, &failed).Fill(&out, test.stat); err != nil {
				t.Fatalf("Fill: %v", err)
			}

			if out.String() != test.want {
				t.Errorf("filled %q, want %q", out.String(), test.want)
			}
		})
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

// TestLogAboveBarsOnlyOnTerminal covers output that isn't a terminal,
// where bars aren't drawn and mpb never flushes what's written to it: log
// lines must keep going where they did, not into the bars' container.
func TestLogAboveBarsOnlyOnTerminal(t *testing.T) {
	var logs strings.Builder
	restoreCapture := logging.SetOutput(&logs)
	defer restoreCapture()

	var out bytes.Buffer
	mb := newMultiBar(&out)
	restore := logAboveBars(mb, &out)
	logging.New(false).Info("during transfer")
	restore()
	mb.Wait()

	if !strings.Contains(logs.String(), "during transfer") {
		t.Errorf("log output = %q, want the line written during the transfer", logs.String())
	}
}
