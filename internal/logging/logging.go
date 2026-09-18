// Package logging configures bomify's log/slog-based CLI logging: leveled,
// human-readable lines on stderr, colored when stderr is a terminal, via
// github.com/lmittmann/tint's zero-dependency slog.Handler.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/lmittmann/tint"
)

const noColorEnv = "NO_COLOR"

// New returns a logger that writes leveled log lines to stderr, colored
// when stderr is a terminal. Debug-level messages are enabled only when
// verbose is true.
func New(verbose bool) *slog.Logger {
	return newLogger(os.Stderr, !SupportsColor(os.Stderr), verbose)
}

// NewFile returns a logger that writes leveled log lines to w — typically
// an open log file. Debug-level messages are enabled only when verbose is
// true; color enables ANSI color codes in the output.
//
// Plugin binaries use this to log to the file named by their --log flag
// (see plugins/CONTRACT.md), passing --log-color through as color: only
// bomify, which streams that file to its own stdout, knows whether those
// bytes will land on a real terminal.
func NewFile(w io.Writer, color, verbose bool) *slog.Logger {
	return newLogger(w, !color, verbose)
}

func newLogger(w io.Writer, noColor, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	return slog.New(tint.NewTextHandler(w, &tint.Options{
		Level:      level,
		NoColor:    noColor,
		TimeFormat: "15:04:05",
	}))
}

type ctxKey struct{}

// WithContext returns a copy of ctx carrying logger, retrievable with FromContext.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, logger)
}

// FromContext returns the logger stored in ctx by WithContext, or
// slog.Default() if none is present.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// SupportsColor returns true if f is a terminal and the NO_COLOR
// environment variable is not set.
func SupportsColor(f *os.File) bool {
	if os.Getenv(noColorEnv) != "" {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
