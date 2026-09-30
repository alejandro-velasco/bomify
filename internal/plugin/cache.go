package plugin

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"

	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
)

// This file holds Pull's bookkeeping: the pid file claimed while a pull
// is in flight, and the manifest recorded once it succeeds — the two
// things that let concurrent and repeated pulls of one component share a
// single fetch.

// pull is Pull's pid-file/manifest bookkeeping around fetch, which writes
// component into the (freshly emptied) directory it's given and reports
// the result — a plugin subprocess for Pull, a local copy for PullBinary.
func pull(component cdx.Component, baseDir string, fetch func(dir string) (*pluginlib.Result, error)) (*pluginlib.Result, error) {
	dir := layout.ComponentLayer(baseDir, component.PackageURL)
	pid := layout.ComponentPID(baseDir, component.PackageURL)
	manifest := layout.ComponentManifest(baseDir, component.PackageURL)

	for {
		if owner, ok := readPID(pid); ok {
			if processAlive(owner) {
				waitForPIDFile(pid, owner)
				continue
			}

			// Stale pid file: a previous pull crashed before cleaning up.
			// Its leftovers in dir are discarded below, along with any
			// other reason dir might already have content.
			os.Remove(pid)
		} else if m, err := readManifest(manifest); err == nil {
			// Nothing is pulling right now, and a prior pull already
			// succeeded: reuse it instead of pulling again. Still verify
			// it against this call's component before trusting it.
			result := &pluginlib.Result{
				OutputPath: dir,
				Message:    "reused prior pull",
				Hash:       manifestHash(m),
			}
			if err := verifyHash(component, result); err != nil {
				return nil, err
			}
			return result, nil
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

		// dir can already have content here — a stale pid's leftovers, or
		// (see the package doc comment) a component restored via `bomify
		// pull` instead of `bomify build`. Either way the plugin contract
		// guarantees --output starts empty, so clear it unconditionally.
		if err := os.RemoveAll(dir); err != nil {
			return nil, fmt.Errorf("clear component directory %s: %w", dir, err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create component directory %s: %w", dir, err)
		}

		result, err := fetch(dir)
		if err != nil {
			os.RemoveAll(dir)
			return nil, err
		}

		if err := verifyHash(component, result); err != nil {
			os.RemoveAll(dir)
			return nil, err
		}

		if err := WriteManifest(baseDir, component, result.Hash); err != nil {
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

// manifestHash returns the HashAlgorithm Hash m's component declares, or
// the zero Hash if it declares none.
func manifestHash(m Manifest) pluginlib.Hash {
	if m.Component.Hashes == nil {
		return pluginlib.Hash{}
	}

	for _, h := range *m.Component.Hashes {
		if h.Algorithm == HashAlgorithm {
			return pluginlib.Hash{Algorithm: h.Algorithm, Value: h.Value}
		}
	}

	return pluginlib.Hash{}
}

// WriteManifest records component (with computed merged into its Hashes)
// as the manifest for baseDir's component directory. Pass the zero Hash
// to leave component's existing Hashes untouched when there's nothing
// new to merge in.
func WriteManifest(baseDir string, component cdx.Component, computed pluginlib.Hash) error {
	if computed.Algorithm != "" {
		component.Hashes = mergeHash(component.Hashes, computed)
	}

	return fsutil.WriteJSON(layout.ComponentManifest(baseDir, component.PackageURL), Manifest{Component: component})
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

// PIDFileLive reports whether path names a pid file whose owning process
// is still alive — i.e. whether a pull is genuinely still in flight for
// whatever component that pid file belongs to (see layout.PID). A missing
// file is not live, and neither is one left behind by a pull that
// crashed without cleaning up (see Pull's own stale-pid handling): only
// Prune calls this, to avoid reclaiming a component out from under a
// pull that's actually still running.
func PIDFileLive(path string) bool {
	pid, ok := readPID(path)
	return ok && processAlive(pid)
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
