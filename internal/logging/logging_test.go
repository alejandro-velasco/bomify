package logging

import (
	"context"
	"log/slog"
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
