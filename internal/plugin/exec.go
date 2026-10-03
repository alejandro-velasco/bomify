package plugin

import (
	cdx "github.com/CycloneDX/cyclonedx-go"

	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
)

// Invoke runs the plugin binary at path with args and returns its stdout
// parsed as T — the single JSON result every plugin contract bomify
// parses has a plugin print on success. On failure, the plugin's stderr
// (its one fatal message) is folded into the returned error.
func Invoke[T any](path string, args ...string) (T, error) {
	var result T
	label := strings.Join(args[:min(2, len(args))], " ")

	cmd := exec.Command(path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return result, fmt.Errorf("run plugin %s %s: %w%s", path, label, err, formatStderr(stderr.String()))
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return result, fmt.Errorf("parse output of plugin %s %s: %w", path, label, err)
	}
	return result, nil
}

// logStreamPollInterval is how often streamLog checks a plugin's log file
// for new content while the plugin is still running.
const logStreamPollInterval = 100 * time.Millisecond

// runComponent is Invoke for the component contract's "component <verb>" (see
// plugins/contracts/component/v1/CONTRACT.md), passing component's purl, its
// log file (as --log), and extraArgs. It creates the log file fresh before
// starting the plugin and — if logger has debug logging enabled (bomify was
// run with --verbose) — streams its content live to stdout for the duration
// of the run; either way, the file exists only to make that streaming
// possible, so it's removed again once the plugin exits.
func runComponent[T any](path, verb string, component cdx.Component, baseDir string, logger *slog.Logger, extraArgs ...string) (*T, error) {
	logFile := layout.ComponentLog(baseDir, component.PackageURL)
	verbose := logger.Enabled(context.Background(), slog.LevelDebug)

	if err := prepareLogFile(logFile); err != nil {
		return nil, err
	}
	defer os.Remove(logFile)

	// Only worth telling the plugin to color its log output if it's
	// actually going to be streamed somewhere that renders color: bomify's
	// own stdout, and only when verbose (streamLog runs at all).
	color := verbose && logging.SupportsColor(os.Stdout)

	if verbose {
		prefix := verb + " " + component.PackageURL
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			streamLog(logFile, prefix, stop)
		}()
		defer func() {
			close(stop)
			<-done
		}()
	}

	args := append([]string{"component", verb, "--purl", component.PackageURL, "--log", logFile, fmt.Sprintf("--log-color=%t", color)}, extraArgs...)
	result, err := Invoke[T](path, args...)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// prepareLogFile creates (truncating if necessary) an empty file at path,
// so a plugin's log always starts fresh for this run and streamLog has
// something to open immediately without racing the plugin's own first
// write to it.
func prepareLogFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create logs directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create log file %s: %w", path, err)
	}

	return f.Close()
}

// streamLog tails path, writing each complete line appended to it to
// stdout — prefixed with "[prefix] " so lines from concurrent pulls/pushes
// streaming at once stay distinguishable — until stop is closed, at which
// point it does one final read to flush anything written (plus any
// trailing, not yet newline-terminated line) just before stopping. path is
// assumed to already exist (see prepareLogFile).
func streamLog(path, prefix string, stop <-chan struct{}) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var pending []byte
	buf := make([]byte, 4096)

	drain := func() {
		for {
			n, err := f.Read(buf)
			if n > 0 {
				pending = append(pending, buf[:n]...)
				pending = writeLogLines(os.Stdout, prefix, pending)
			}
			if err != nil {
				return
			}
		}
	}

	for {
		drain()

		select {
		case <-stop:
			drain()
			if len(pending) > 0 {
				fmt.Fprintf(os.Stdout, "[%s] %s\n", prefix, pending)
			}
			return
		case <-time.After(logStreamPollInterval):
		}
	}
}

// writeLogLines writes every complete ("\n"-terminated) line in data to w,
// each prefixed with "[prefix] ", and returns whatever trailing partial
// line remains (with no newline yet, since the writer may not be done
// with it) for the caller to prepend to data on its next call.
func writeLogLines(w io.Writer, prefix string, data []byte) []byte {
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return data
		}
		fmt.Fprintf(w, "[%s] %s\n", prefix, data[:i])
		data = data[i+1:]
	}
}

func formatStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}
