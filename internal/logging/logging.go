// Package logging configures bomify's log/slog-based CLI logging: leveled,
// human-readable lines on stderr, colored when stderr is a terminal, via
// github.com/lmittmann/tint's zero-dependency slog.Handler.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/lmittmann/tint"
	"github.com/opencontainers/go-digest"
)

const noColorEnv = "NO_COLOR"

// New returns a logger that writes leveled log lines to stderr, or where
// SetOutput redirects them, colored when stderr is a terminal.
// Debug-level messages are enabled only when verbose is true.
func New(verbose bool) *slog.Logger {
	return newLogger(output, !SupportsColor(os.Stderr), verbose)
}

// output is where New's loggers write.
var output = &redirectWriter{fallback: os.Stderr}

// SetOutput sends the lines New's loggers write to w until the returned
// restore is called. Progress bars use it so log lines print above them
// (see mpb's (*Progress).Write) rather than through them: a line written
// straight to stderr while bars are drawn leaves stale copies of them on
// screen, misaligned with the bars redrawn below it.
func SetOutput(w io.Writer) (restore func()) {
	output.set(w)
	return func() { output.set(nil) }
}

// redirectWriter writes to w if set, else to fallback, and to fallback
// too if w fails, as a progress container does once it's shut down, so a
// line is never lost.
type redirectWriter struct {
	mu       sync.Mutex
	w        io.Writer
	fallback io.Writer
}

func (r *redirectWriter) set(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.w = w
}

func (r *redirectWriter) Write(b []byte) (int, error) {
	r.mu.Lock()
	w := r.w
	r.mu.Unlock()
	if w != nil {
		if n, err := w.Write(b); err == nil {
			return n, nil
		}
	}
	return r.fallback.Write(b)
}

// NewFile returns a logger that writes leveled log lines to w — typically
// an open log file. Debug-level messages are enabled only when verbose is
// true; color enables ANSI color codes in the output.
//
// Plugin binaries use this to log to the file named by their --log flag (see
// plugins/contracts/component/v1/CONTRACT.md), passing --log-color through as
// color: only bomify, which streams that file to its own stdout, knows
// whether those bytes will land on a real terminal.
func NewFile(w io.Writer, color, verbose bool) *slog.Logger {
	return newLogger(w, !color, verbose)
}

// Colors (ANSI 256-color indexes) for attribute values, by what they are.
const (
	// colorError is the only color bomify adds to tint's level colors:
	// bright red, from the terminal theme's palette, for error values. Other
	// values stay uncolored, so nothing becomes unreadable on a light or
	// low-contrast theme, and color is never the only signal.
	colorError = 9
	// shortDigestHex is how many hex digits of a digest are logged unless
	// verbose.
	shortDigestHex = 12
)

func newLogger(w io.Writer, noColor, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	return slog.New(tint.NewTextHandler(w, &tint.Options{
		Level:       level,
		NoColor:     noColor,
		TimeFormat:  "15:04:05",
		ReplaceAttr: replaceAttr(verbose),
	}))
}

// replaceAttr colors error values red and, unless verbose, cuts digests
// to their first shortDigestHex hex digits and drops the time, which a
// CLI run's lines all share nearly the same of.
func replaceAttr(verbose bool) func(groups []string, attr slog.Attr) slog.Attr {
	return func(groups []string, attr slog.Attr) slog.Attr {
		if len(groups) > 0 {
			return attr
		}
		if _, ok := attr.Value.Any().(error); ok {
			return tint.Attr(colorError, attr)
		}
		if verbose {
			return attr
		}
		if attr.Key == slog.TimeKey {
			return slog.Attr{}
		}
		if attr.Value.Kind() != slog.KindString {
			return attr
		}
		value := attr.Value.String()
		// bomify logs SHA-256 hashes as bare hex too, e.g. hash=4ecc2cd4….
		bare := !strings.Contains(value, ":")
		d := digest.Digest(value)
		if bare {
			d = digest.NewDigestFromEncoded(digest.SHA256, value)
		}
		if d.Validate() != nil {
			return attr
		}
		short := d.Encoded()[:shortDigestHex] + "…"
		if !bare {
			short = string(d.Algorithm()) + ":" + short
		}
		attr.Value = slog.StringValue(short)
		return attr
	}
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

// WarningsOnly returns logger, dropping everything below warning level —
// what a command's --quiet leaves on stderr.
func WarningsOnly(logger *slog.Logger) *slog.Logger {
	return slog.New(minLevelHandler{Handler: logger.Handler(), min: slog.LevelWarn})
}

// minLevelHandler is Handler, disabled below min.
type minLevelHandler struct {
	slog.Handler
	min slog.Level
}

func (h minLevelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.min && h.Handler.Enabled(ctx, level)
}

func (h minLevelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return minLevelHandler{Handler: h.Handler.WithAttrs(attrs), min: h.min}
}

func (h minLevelHandler) WithGroup(name string) slog.Handler {
	return minLevelHandler{Handler: h.Handler.WithGroup(name), min: h.min}
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
