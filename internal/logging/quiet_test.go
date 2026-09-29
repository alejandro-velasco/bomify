package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestWarningsOnly covers what a command's --quiet leaves on stderr:
// warnings and errors, including from loggers derived with With, but
// nothing informational.
func TestWarningsOnly(t *testing.T) {
	var buf bytes.Buffer
	logger := WarningsOnly(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))).With("component", "x")

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	out := buf.String()
	for _, dropped := range []string{"debug message", "info message"} {
		if strings.Contains(out, dropped) {
			t.Errorf("--quiet logged %q:\n%s", dropped, out)
		}
	}
	for _, kept := range []string{"warn message", "error message", "component=x"} {
		if !strings.Contains(out, kept) {
			t.Errorf("--quiet dropped %q:\n%s", kept, out)
		}
	}
}
