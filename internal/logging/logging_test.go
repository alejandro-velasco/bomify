package logging

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/lmittmann/tint"
)

func TestNewRespectsVerbose(t *testing.T) {
	logger := New(false)
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("New(false) logger has debug enabled, want disabled")
	}
	if !logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("New(false) logger has info disabled, want enabled")
	}

	verboseLogger := New(true)
	if !verboseLogger.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("New(true) logger has debug disabled, want enabled")
	}
}

func TestNewFileColor(t *testing.T) {
	var buf strings.Builder
	NewFile(&buf, true, false).Info("msg")

	if !strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("output %q has no ANSI escape codes, want color enabled", buf.String())
	}
}

func TestNewFileNoColor(t *testing.T) {
	var buf strings.Builder
	NewFile(&buf, false, false).Info("msg")

	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("output %q contains ANSI escape codes, want color disabled", buf.String())
	}
}

func TestContextRoundTrip(t *testing.T) {
	logger := New(true)

	ctx := WithContext(context.Background(), logger)
	if got := FromContext(ctx); got != logger {
		t.Errorf("FromContext() = %p, want %p", got, logger)
	}
}

func TestFromContextDefault(t *testing.T) {
	if got := FromContext(context.Background()); got != slog.Default() {
		t.Errorf("FromContext(background) = %p, want slog.Default() %p", got, slog.Default())
	}
}

func newTintLogger(w *strings.Builder, noColor bool) *slog.Logger {
	return slog.New(tint.NewTextHandler(w, &tint.Options{
		Level:   slog.LevelInfo,
		NoColor: noColor,
	}))
}

func TestLoggerOutputsMessageAndAttrs(t *testing.T) {
	var buf strings.Builder

	logger := newTintLogger(&buf, true).With("component", "nginx")
	logger.Info("delegating to plugin", "kind", "docker")

	out := buf.String()
	for _, want := range []string{"INF", "delegating to plugin", "component=nginx", "kind=docker"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q does not contain %q", out, want)
		}
	}
}

func TestLoggerQuotesValuesWithSpaces(t *testing.T) {
	var buf strings.Builder

	newTintLogger(&buf, true).Info("msg", "path", "has space")

	if want := `path="has space"`; !strings.Contains(buf.String(), want) {
		t.Errorf("output %q does not contain %q", buf.String(), want)
	}
}

func TestLoggerNoColorWhenDisabled(t *testing.T) {
	var buf strings.Builder

	newTintLogger(&buf, true).Info("msg")

	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("output %q contains ANSI escape codes with color disabled", buf.String())
	}
}

func TestStyledLines(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	logLine := func(verbose bool) string {
		var buf strings.Builder
		NewFile(&buf, false, verbose).Info("signed", "reference", "app:1.0", "manifest", digest, "hash", strings.Repeat("cd", 32))
		return buf.String()
	}

	got := logLine(false)
	want := "INF signed reference=app:1.0 manifest=sha256:abababababab… hash=cdcdcdcdcdcd…\n"
	if got != want {
		t.Errorf("line = %q, want %q (no time, digests cut)", got, want)
	}

	verboseLine := logLine(true)
	if !strings.Contains(verboseLine, "manifest="+digest) || strings.HasPrefix(verboseLine, "INF") {
		t.Errorf("verbose line = %q, want the time and full digests", verboseLine)
	}
}

func TestStyledColors(t *testing.T) {
	var buf strings.Builder
	NewFile(&buf, true, false).Error("failed", "reference", "app:1.0", "error", errors.New("boom"), "path", "x")
	out := buf.String()

	// tint writes colors 0-15 as the short ANSI codes, faint for the key.
	for _, want := range []string{
		"\x1b[2;91merror=\x1b[22mboom",    // errors, bright red
		"\x1b[2mreference=\x1b[0mapp:1.0", // everything else, uncolored
		"\x1b[2mpath=\x1b[0mx",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q missing %q", out, want)
		}
	}
}

func TestDigestsShortened(t *testing.T) {
	hexDigits := strings.Repeat("0f", 32)
	for value, want := range map[string]string{
		"sha256:" + hexDigits:      "sha256:0f0f0f0f0f0f…",
		hexDigits:                  "0f0f0f0f0f0f…",
		"sha256:" + hexDigits[:10]: "sha256:" + hexDigits[:10],
		strings.ToUpper(hexDigits): strings.ToUpper(hexDigits),
		"key sha256:not-a-digest":  `"key sha256:not-a-digest"`,
		"app:1.0":                  "app:1.0",
	} {
		var buf strings.Builder
		NewFile(&buf, false, false).Info("m", "value", value)
		if got := strings.TrimSuffix(strings.TrimPrefix(buf.String(), "INF m value="), "\n"); got != want {
			t.Errorf("value %q logged as %q, want %q", value, got, want)
		}
	}
}

func TestSetOutputRedirectsAndRestores(t *testing.T) {
	var fallback, redirected strings.Builder
	w := &redirectWriter{fallback: &fallback}

	w.Write([]byte("before\n"))
	w.set(&redirected)
	w.Write([]byte("during\n"))
	w.set(nil)
	w.Write([]byte("after\n"))

	if fallback.String() != "before\nafter\n" || redirected.String() != "during\n" {
		t.Errorf("fallback = %q, redirected = %q; want before/after and during", fallback.String(), redirected.String())
	}
}

// TestSetOutputFallsBack covers a progress container already shut down,
// whose Write fails: the line goes to stderr instead of being lost.
func TestSetOutputFallsBack(t *testing.T) {
	var fallback strings.Builder
	w := &redirectWriter{fallback: &fallback}
	w.set(failingWriter{})

	if _, err := w.Write([]byte("line\n")); err != nil || fallback.String() != "line\n" {
		t.Errorf("Write = %v, fallback = %q; want the line on the fallback", err, fallback.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("done") }

func TestNewWritesToSetOutput(t *testing.T) {
	var buf strings.Builder
	restore := SetOutput(&buf)
	New(false).Info("hello")
	restore()

	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("redirected output = %q, want the log line", buf.String())
	}
}

func TestIsTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f) || IsTerminal(&strings.Builder{}) {
		t.Error("IsTerminal = true for a regular file or a buffer, want false")
	}
}
