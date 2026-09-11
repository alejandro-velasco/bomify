// Package logging configures bomify's log/slog-based CLI logging: leveled,
// human-readable lines on stderr, colored when stderr is a terminal.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns a logger that writes leveled log lines to stderr. Debug-level
// messages are enabled only when verbose is true.
func New(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	return slog.New(&handler{
		out:   os.Stderr,
		level: level,
		color: supportsColor(os.Stderr),
	})
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

// handler is a small, dependency-free slog.Handler that prints a time,
// colored level, message, and "key=value" attributes on a single line.
type handler struct {
	out    io.Writer
	level  slog.Level
	color  bool
	attrs  []slog.Attr
	groups []string
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	b.WriteString(r.Time.Format("15:04:05"))
	b.WriteByte(' ')
	b.WriteString(h.formatLevel(r.Level))
	b.WriteByte(' ')
	b.WriteString(r.Message)

	for _, a := range h.attrs {
		h.writeAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		h.writeAttr(&b, a)
		return true
	})

	b.WriteByte('\n')

	_, err := io.WriteString(h.out, b.String())
	return err
}

func (h *handler) writeAttr(b *strings.Builder, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}

	b.WriteByte(' ')
	for _, g := range h.groups {
		b.WriteString(g)
		b.WriteByte('.')
	}
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(formatValue(a.Value))
}

func formatValue(v slog.Value) string {
	s := v.String()
	if strings.ContainsAny(s, " \"") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// levelColors maps a minimum level to its ANSI color code.
var levelColors = []struct {
	level slog.Level
	code  string
}{
	{slog.LevelError, "31"}, // red
	{slog.LevelWarn, "33"},  // yellow
	{slog.LevelInfo, "36"},  // cyan
}

func (h *handler) formatLevel(level slog.Level) string {
	label := fmt.Sprintf("%-5s", level.String())
	if !h.color {
		return label
	}

	code := "90" // gray, for debug and below
	for _, lc := range levelColors {
		if level >= lc.level {
			code = lc.code
			break
		}
	}

	return "\x1b[" + code + "m" + label + "\x1b[0m"
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &clone
}

func (h *handler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.groups = append(append([]string{}, h.groups...), name)
	return &clone
}
