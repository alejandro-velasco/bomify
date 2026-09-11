package plugin

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/alejandro-velasco/bomify/internal/logging"
)

// OpenLog opens path — the file named by a plugin invocation's --log flag
// (see the package doc comment) — for appending, and returns a logger
// writing to it in the same format bomify's own CLI logging uses, plus a
// close func the caller should defer. color should be whatever value the
// plugin's --log-color flag was given, and enables ANSI color codes in
// the logged lines to match. Plugin binaries should use this instead of
// constructing their own logger, since they must not write general
// logging to stdout or stderr (see the package doc comment).
func OpenLog(path string, color bool) (*slog.Logger, func() error, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %s: %w", path, err)
	}

	return logging.NewFile(f, color, true), f.Close, nil
}
