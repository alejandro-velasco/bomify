package plugin

import (
	cdx "github.com/CycloneDX/cyclonedx-go"

	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
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

// tailPollInterval is how often follow checks a file for new lines while
// a plugin is still running.
const tailPollInterval = 100 * time.Millisecond

// runComponent is Invoke for the component contract's "component <verb>"
// (see plugins/contracts/component/v1/CONTRACT.md), passing component's
// purl, its log file (see pluginLog), and extraArgs.
//
// With a tracker, it also passes a progress file (as --progress), created
// and removed the same way, and shows the plugin's run and the events it
// reports there through the tracker.
func runComponent[T any](path, verb string, component cdx.Component, baseDir string, logger *slog.Logger, tracker Tracker, extraArgs ...string) (*T, error) {
	logArgs, stopLog, err := pluginLog(layout.ComponentLog(baseDir, component.PackageURL), verb+" "+component.PackageURL, logger)
	if err != nil {
		return nil, err
	}
	defer stopLog()
	args := append([]string{pluginlib.ComponentSubcommand, verb, "--purl", component.PackageURL}, logArgs...)
	args = append(args, extraArgs...)

	if tracker == nil {
		result, err := Invoke[T](path, args...)
		if err != nil {
			return nil, err
		}
		return &result, nil
	}

	progressFile := layout.ComponentProgress(baseDir, component.PackageURL)
	if err := prepareFile(progressFile); err != nil {
		return nil, err
	}
	defer os.Remove(progressFile)
	args = append(args, "--progress", progressFile)

	pulling := tracker.Start(component.PackageURL)
	stopProgress := follow(progressFile, func(line []byte) {
		showProgress(pulling, line)
	})
	result, err := Invoke[T](path, args...)
	stopProgress()
	pulling.Done(err == nil)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// pluginLog creates logFile fresh, for a plugin call's --log, and, if
// logger has debug logging enabled (bomify was run with --verbose),
// prints its lines with bomify's own log (see logging.Output), each
// prefixed with "[prefix] ", as the plugin writes them. It returns the
// --log and --log-color arguments, and stop, which ends that and removes
// the file: it exists only for the printing.
func pluginLog(logFile, prefix string, logger *slog.Logger) (args []string, stop func(), err error) {
	if err := prepareFile(logFile); err != nil {
		return nil, nil, err
	}
	verbose := logger.Enabled(context.Background(), slog.LevelDebug)
	// Only worth telling the plugin to color its log if it's going to be
	// printed somewhere that renders color: with bomify's own log, and only
	// when verbose.
	color := verbose && logging.SupportsColor(os.Stderr)
	args = []string{"--log", logFile, fmt.Sprintf("--log-color=%t", color)}

	stopFollowing := func() {}
	if verbose {
		stopFollowing = follow(logFile, func(line []byte) {
			fmt.Fprintf(logging.Output(), "[%s] %s\n", prefix, line)
		})
	}
	stop = func() {
		stopFollowing()
		os.Remove(logFile)
	}
	return args, stop, nil
}

// prepareFile creates (truncating if necessary) an empty file at path, so
// a plugin's log or progress always starts fresh for this run and follow
// has something to open immediately without racing the plugin's own first
// write to it.
func prepareFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create logs directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}

	return f.Close()
}

// follow calls line with each line appended to path, which must exist,
// until the returned stop is called. stop returns once every line written
// by then, including a last one with no newline yet, has been handled.
func follow(path string, line func([]byte)) (stop func()) {
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tail(path, quit, line)
	}()
	return func() {
		close(quit)
		<-done
	}
}

// tail is follow's loop: it reads path every tailPollInterval until quit
// is closed, then once more.
func tail(path string, quit <-chan struct{}, line func([]byte)) {
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
				pending = splitLines(pending, line)
			}
			if err != nil {
				return
			}
		}
	}

	for {
		drain()

		select {
		case <-quit:
			drain()
			if len(pending) > 0 {
				line(pending)
			}
			return
		case <-time.After(tailPollInterval):
		}
	}
}

// splitLines calls line with every complete ("\n"-terminated) line in
// data, without its newline, and returns whatever trailing partial line
// remains (the writer may not be done with it) for the caller to prepend
// to data on its next call.
func splitLines(data []byte, line func([]byte)) []byte {
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return data
		}
		line(data[:i])
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
