// Package plugin dispatches SBOM components to external "bomify-plugin-*"
// helper binaries, letting bomify delegate component types it doesn't know
// how to build itself (e.g. container images) to a separate executable.
// See plugins/CONTRACT.md for the full subprocess contract a plugin must
// implement, and pkg/plugin for the Go library (Result, Hash, Print,
// OpenLog) a plugin author — first- or third-party — implements it with;
// this package is bomify's own caller-side orchestration around that
// contract, not importable outside this module.
//
// Pull is safe to call concurrently, even from separate bomify processes,
// for components that hash to the same directory (e.g. duplicate purls
// within or across SBOMs): if a pid file already names a live process,
// Pull waits for it instead of pulling again; if that pid file is stale
// (its process is gone without cleaning up, e.g. it crashed), Pull
// discards the leftover directory and pulls fresh; if neither a pid file
// nor a manifest exists, Pull pulls; if a manifest already exists and
// nothing is pulling, Pull reuses it. Whichever of those applies, Pull
// finishes by verifying the resulting hash as described below, so even a
// reused result fails if it doesn't match this call's component.
package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/alejandro-velasco/bomify/internal/logging"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// binaryPrefix precedes the kind in a plugin's executable name.
const binaryPrefix = "bomify-plugin-"

// hashAlgorithms lists the CycloneDX hash algorithms recognized by
// NormalizeHashAlgorithm.
var hashAlgorithms = []cdx.HashAlgorithm{
	cdx.HashAlgoMD5,
	cdx.HashAlgoSHA1,
	cdx.HashAlgoSHA256,
	cdx.HashAlgoSHA384,
	cdx.HashAlgoSHA512,
	cdx.HashAlgoSHA3_256,
	cdx.HashAlgoSHA3_384,
	cdx.HashAlgoSHA3_512,
	cdx.HashAlgoBlake2b_256,
	cdx.HashAlgoBlake2b_384,
	cdx.HashAlgoBlake2b_512,
	cdx.HashAlgoBlake3,
	cdx.HashAlgoStreebog256,
	cdx.HashAlgoStreebog512,
}

// NormalizeHashAlgorithm resolves a case- and hyphen-insensitive hash
// algorithm name, such as one passed via a --hash flag (e.g. "sha-256" or
// "sha256"), to its canonical CycloneDX form (e.g. "SHA-256"). It returns
// an error if name isn't a recognized CycloneDX hash algorithm.
func NormalizeHashAlgorithm(name string) (cdx.HashAlgorithm, error) {
	fold := func(s string) string {
		return strings.ToUpper(strings.ReplaceAll(s, "-", ""))
	}

	target := fold(name)
	for _, alg := range hashAlgorithms {
		if fold(string(alg)) == target {
			return alg, nil
		}
	}

	return "", fmt.Errorf("unrecognized hash algorithm %q", name)
}

// Detect returns the plugin kind corresponding to the given SBOM
// component's purl type (e.g. "oci" for "pkg:oci/nginx@sha256:abc"),
// which is also the kind passed to BinaryName to locate the plugin
// binary. It requires component to carry a purl, returning an error if it
// doesn't.
func Detect(component cdx.Component) (string, error) {
	if component.PackageURL == "" {
		return "", fmt.Errorf("component %s@%s has no package URL", component.Name, component.Version)
	}

	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		return "", fmt.Errorf("parse package URL: %w", err)
	}

	return purl.Type, nil
}

// BinaryName returns the expected executable name for the plugin handling
// kind, e.g. BinaryName("docker") == "bomify-plugin-docker".
func BinaryName(kind string) string {
	return binaryPrefix + kind
}

// Find resolves the plugin binary for kind by searching PATH. It returns an
// error if no such plugin is installed.
func Find(kind string) (string, error) {
	name := BinaryName(kind)

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("plugin %q not found on PATH: %w", name, err)
	}

	return path, nil
}

// Pull invokes the plugin binary's "pull" subcommand, which fetches or
// builds component and writes it into componentDir's directory. Pull
// creates that directory before invoking the plugin and removes it again
// if the plugin fails.
//
// hashAlgorithm is passed to the plugin via --hash, asking it to report
// the pulled artifact's content hash. If component declares its own hash
// for that algorithm in its SBOM metadata, Pull verifies the two match —
// removing dir and failing on a mismatch for a pull this call just
// performed, or failing without touching dir when reusing a concurrent
// or prior pull's result, since this call doesn't own it. Verification is
// skipped if either side has no hash to compare.
//
// Pull is safe to call concurrently — including from separate bomify
// processes — for components that hash to the same directory (e.g.
// duplicate purls within or across SBOMs). See the package doc comment
// for the exact rules it follows to avoid pulling the same component
// twice at once.
//
// logger controls whether the plugin's own log file is streamed live to
// stdout while it runs: it is if logger has debug-level logging enabled
// (i.e. bomify was run with --verbose), and isn't otherwise.
func Pull(path string, component cdx.Component, baseDir string, hashAlgorithm cdx.HashAlgorithm, logger *slog.Logger) (*pluginlib.Result, error) {
	dir := componentDir(baseDir, component)
	pid := pidPath(baseDir, component)
	manifest := manifestPath(baseDir, component)
	logFile := logPath(baseDir, component)
	verbose := logger.Enabled(context.Background(), slog.LevelDebug)

	for {
		if owner, ok := readPID(pid); ok {
			if processAlive(owner) {
				waitForPIDFile(pid, owner)
				continue
			}

			// Stale pid file: a previous pull crashed before cleaning up.
			// Discard its leftovers and pull fresh below.
			os.Remove(pid)
			os.RemoveAll(dir)
		} else if m, err := readManifest(manifest); err == nil {
			// Nothing is pulling right now, and a prior pull already
			// succeeded: reuse it instead of pulling again. Still verify
			// it against this call's component before trusting it.
			result := &pluginlib.Result{
				OutputPath: dir,
				Message:    "reused prior pull",
				Hash:       manifestHash(m, hashAlgorithm),
			}
			if err := verifyHash(component, result); err != nil {
				return nil, err
			}
			return result, nil
		}

		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create component directory %s: %w", dir, err)
		}

		if err := os.MkdirAll(filepath.Dir(pid), 0o755); err != nil {
			return nil, fmt.Errorf("create manifests directory: %w", err)
		}

		if err := claimPIDFile(pid); err != nil {
			if os.IsExist(err) {
				// Lost a race with another process claiming this pull;
				// re-evaluate from the top instead of pulling twice.
				continue
			}
			return nil, fmt.Errorf("claim pid file %s: %w", pid, err)
		}
		defer os.Remove(pid)

		result, err := run(path, "pull", component.PackageURL, logFile, verbose, "--output", dir, "--hash", string(hashAlgorithm))
		if err != nil {
			os.RemoveAll(dir)
			return nil, err
		}

		if err := verifyHash(component, result); err != nil {
			os.RemoveAll(dir)
			return nil, err
		}

		if err := writeManifest(baseDir, component, result.Hash); err != nil {
			os.RemoveAll(dir)
			return nil, err
		}

		return result, nil
	}
}

// pidPollInterval is how often Pull re-checks another process's pid file
// while waiting for its pull to finish.
const pidPollInterval = 100 * time.Millisecond

// Manifest is the record Pull writes to
// "<baseDir>/manifests/<purl-hash>.json" after a successful pull. Its
// existence at that path is the authoritative signal that the pull for
// the component it describes succeeded.
type Manifest struct {
	// Component is the SBOM component that was pulled, with the hash
	// computed during that pull (if any) merged into its Hashes.
	Component cdx.Component `json:"component"`
}

// readManifest reads and parses the manifest at path.
func readManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest %s: %w", path, err)
	}

	return m, nil
}

// manifestHash returns the Hash m's component declares for hashAlgorithm,
// or the zero Hash if it declares none for that algorithm.
func manifestHash(m Manifest, hashAlgorithm cdx.HashAlgorithm) pluginlib.Hash {
	if m.Component.Hashes == nil {
		return pluginlib.Hash{}
	}

	for _, h := range *m.Component.Hashes {
		if h.Algorithm == hashAlgorithm {
			return pluginlib.Hash{Algorithm: h.Algorithm, Value: h.Value}
		}
	}

	return pluginlib.Hash{}
}

// writeManifest records component (with computed merged into its Hashes,
// if set) as the manifest for baseDir's component directory.
func writeManifest(baseDir string, component cdx.Component, computed pluginlib.Hash) error {
	if computed.Algorithm != "" {
		component.Hashes = mergeHash(component.Hashes, computed)
	}

	// json.Marshal HTML-escapes '&', '<', and '>' by default, which would
	// otherwise mangle purl query strings (e.g. "...&tag=..." becomes
	// "...&tag=..."). Encode directly with that disabled instead.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(Manifest{Component: component}); err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	path := manifestPath(baseDir, component)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create manifests directory: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}

	return nil
}

// mergeHash returns existing with computed either replacing the entry for
// the same algorithm or appended, so a component's Hashes always reflects
// the most recently computed value for that algorithm.
func mergeHash(existing *[]cdx.Hash, computed pluginlib.Hash) *[]cdx.Hash {
	hashes := []cdx.Hash{}
	if existing != nil {
		hashes = append(hashes, *existing...)
	}

	for i, h := range hashes {
		if h.Algorithm == computed.Algorithm {
			hashes[i].Value = computed.Value
			return &hashes
		}
	}

	hashes = append(hashes, cdx.Hash{Algorithm: computed.Algorithm, Value: computed.Value})
	return &hashes
}

// verifyHash checks, when component declares an SBOM hash for the same
// algorithm result.Hash reports, that the two values match.
func verifyHash(component cdx.Component, result *pluginlib.Result) error {
	if result.Hash.Algorithm == "" || component.Hashes == nil {
		return nil
	}

	for _, declared := range *component.Hashes {
		if declared.Algorithm != result.Hash.Algorithm {
			continue
		}
		if !strings.EqualFold(declared.Value, result.Hash.Value) {
			return fmt.Errorf("%s hash mismatch for %s@%s: SBOM declares %s, pulled artifact has %s",
				result.Hash.Algorithm, component.Name, component.Version, declared.Value, result.Hash.Value)
		}
		return nil
	}

	return nil
}

// Push invokes the plugin binary's "push" subcommand, which publishes to
// remote the component a prior call to Pull wrote into baseDir. Push looks
// for that pull's manifest and fails before invoking the plugin if it
// doesn't exist (Pull only writes it after succeeding).
//
// logger controls log streaming exactly as it does for Pull.
func Push(path string, component cdx.Component, baseDir, remote string, logger *slog.Logger) (*pluginlib.Result, error) {
	dir := componentDir(baseDir, component)

	if _, err := os.Stat(manifestPath(baseDir, component)); err != nil {
		return nil, fmt.Errorf("component not found in %s (run bomify build first): %w", dir, err)
	}

	logFile := logPath(baseDir, component)
	verbose := logger.Enabled(context.Background(), slog.LevelDebug)

	return run(path, "push", component.PackageURL, logFile, verbose, "--input", dir, "--remote", remote)
}

// PurlHash returns a hex-encoded hash of component's purl, used to derive
// both componentDir and manifestPath so pull and push independently agree
// on the same locations. It's exported so callers building on top of a
// component's own manifest (e.g. an aggregate build-level manifest) can
// derive the exact same filename without duplicating the hash logic.
func PurlHash(component cdx.Component) string {
	sum := sha256.Sum256([]byte(component.PackageURL))
	return hex.EncodeToString(sum[:])
}

// componentDir returns the deterministic subdirectory of baseDir/layers
// where a component's pulled artifact lives.
func componentDir(baseDir string, component cdx.Component) string {
	return filepath.Join(baseDir, "layers", PurlHash(component))
}

// manifestPath returns the deterministic path of a component's manifest
// file (see Manifest), under baseDir/manifests.
func manifestPath(baseDir string, component cdx.Component) string {
	return filepath.Join(baseDir, "manifests", PurlHash(component)+".json")
}

// logPath returns the deterministic path of a component's plugin log
// file, under baseDir/logs, named after the same purl hash as its
// manifest and layers directory.
func logPath(baseDir string, component cdx.Component) string {
	return filepath.Join(baseDir, "logs", PurlHash(component)+".log")
}

// pidPath returns the deterministic path of a component's pid file, a
// sibling of its manifest under baseDir/manifests. Pull claims this file
// for the duration of a pull and removes it once the pull completes
// (whether it succeeded or failed), so its existence signals a pull
// currently in flight for that component.
func pidPath(baseDir string, component cdx.Component) string {
	return filepath.Join(baseDir, "manifests", PurlHash(component)+".pid")
}

// claimPIDFile atomically creates path containing the current process's
// pid. It returns an error satisfying os.IsExist if path already exists,
// meaning another process claimed it first.
func claimPIDFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		return fmt.Errorf("write pid file %s: %w", path, err)
	}

	return nil
}

// readPID reads the pid recorded at path. ok is false if the file doesn't
// exist or doesn't contain a valid pid.
func readPID(path string) (pid int, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}

	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}

	return n, true
}

// processAlive reports whether a process with the given pid currently
// exists.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	if runtime.GOOS == "windows" {
		// On Windows, os.FindProcess itself opens (and so validates) a
		// handle to the process, so success here already confirms it
		// exists.
		return true
	}

	// On POSIX, os.FindProcess always succeeds regardless of whether pid
	// exists; signal 0 probes for real existence without affecting it.
	return process.Signal(syscall.Signal(0)) == nil
}

// waitForPIDFile blocks until path is removed (the process that owns it
// finished) or owner is no longer alive (it crashed without cleaning up),
// whichever happens first.
func waitForPIDFile(path string, owner int) {
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		if !processAlive(owner) {
			return
		}
		time.Sleep(pidPollInterval)
	}
}

// logStreamPollInterval is how often streamLog checks a plugin's log file
// for new content while the plugin is still running.
const logStreamPollInterval = 100 * time.Millisecond

// run invokes the plugin binary at path with subcommand verb, passing purl,
// logFile (as --log), and the given extra arguments, and returns the
// plugin's parsed result. It creates logFile fresh before starting the
// plugin and, if verbose, streams its content live to stdout for the
// duration of the run; either way, logFile exists only to make that
// streaming possible, so run removes it again once the plugin exits.
func run(path, verb, purl, logFile string, verbose bool, extraArgs ...string) (*pluginlib.Result, error) {
	if err := prepareLogFile(logFile); err != nil {
		return nil, err
	}
	defer os.Remove(logFile)

	// Only worth telling the plugin to color its log output if it's
	// actually going to be streamed somewhere that renders color: bomify's
	// own stdout, and only when verbose (streamLog runs at all).
	color := verbose && logging.SupportsColor(os.Stdout)

	args := append([]string{verb, "--purl", purl, "--log", logFile, fmt.Sprintf("--log-color=%t", color)}, extraArgs...)
	cmd := exec.Command(path, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if verbose {
		prefix := verb + " " + purl
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

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run plugin %s %s: %w%s", path, verb, err, formatStderr(stderr.String()))
	}

	var result pluginlib.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse output of plugin %s %s: %w", path, verb, err)
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
