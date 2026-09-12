// Package logging configures bomify's log/slog-based CLI logging: leveled,
// human-readable lines on stderr, colored when stderr is a terminal, via
// github.com/lmittmann/tint's zero-dependency slog.Handler.
package logging

import (
	"context"
	"log/slog"
	"os"

	"github.com/lmittmann/tint"
)

// New returns a logger that writes leveled log lines to stderr. Debug-level
// messages are enabled only when verbose is true.
func New(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	return slog.New(tint.NewTextHandler(os.Stderr, &tint.Options{
		Level:      level,
		NoColor:    !supportsColor(os.Stderr),
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

// supportsColor returns true if f is a terminal and the NO_COLOR environment
// variable is not set.
func supportsColor(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
