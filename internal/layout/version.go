package layout

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
)

// CurrentVersion is the data directory version this bomify reads and
// writes. It covers the layout and the schemas of the files bomify reads
// back (see docs/architecture/data-directory.md#versioning); changing
// either bumps it and appends a migration to migrations.
const CurrentVersion = 1

// versionFile is the content of VersionFile.
type versionFile struct {
	Version int `json:"version"`
}

// migration upgrades a data directory by one version, in place. It must
// be safe to run again after a crash partway through.
type migration func(dataDir string) error

// migrations[index] upgrades version index+1 to index+2, so there are
// always CurrentVersion-1 of them.
var migrations []migration

// CheckVersion makes dataDir usable by this bomify: it gives a missing or
// empty directory the current version, migrates an older one in place,
// and refuses a newer one, or a non-empty one with no version, which a
// pre-alpha bomify wrote.
func CheckVersion(dataDir string) error {
	return checkVersion(dataDir, CurrentVersion, migrations)
}

func checkVersion(dataDir string, current int, steps []migration) error {
	versionPath := VersionFile(dataDir)
	version, err := readVersion(versionPath)
	if err != nil {
		return err
	}

	if version == 0 {
		return initVersion(dataDir, current)
	}
	if version > current {
		return fmt.Errorf("data directory %s is version %d, but this bomify only supports up to version %d: upgrade bomify, or use another --data-dir", dataDir, version, current)
	}

	// Each step's version is recorded as soon as it succeeds, so a crash
	// resumes from the last completed step.
	for from := version; from < current; from++ {
		if err := steps[from-1](dataDir); err != nil {
			return fmt.Errorf("migrate data directory %s from version %d to %d: %w", dataDir, from, from+1, err)
		}
		if err := writeVersion(versionPath, from+1); err != nil {
			return err
		}
	}
	return nil
}

// readVersion returns the version recorded at versionPath, or 0 if
// there's none.
func readVersion(versionPath string) (int, error) {
	var recorded versionFile
	if err := fsutil.ReadJSON(versionPath, &recorded); err != nil {
		return 0, err
	}
	if recorded.Version < 0 {
		return 0, fmt.Errorf("parse %s: invalid version %d", versionPath, recorded.Version)
	}
	return recorded.Version, nil
}

// initVersion records version in dataDir, which must be missing or
// empty: one with content but no version was written by a pre-alpha
// bomify, whose data never carried over.
func initVersion(dataDir string, version int) error {
	empty, err := isEmptyDir(dataDir)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("data directory %s has no version, so a pre-alpha bomify wrote it: move or delete it and bomify will start a new one, then rebuild or pull your packages", dataDir)
	}
	return writeVersion(VersionFile(dataDir), version)
}

func writeVersion(versionPath string, version int) error {
	recorded := versionFile{
		Version: version,
	}
	return fsutil.WriteJSON(versionPath, recorded)
}

// isEmptyDir reports whether dir is missing or has no entries.
func isEmptyDir(dir string) (bool, error) {
	f, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("open %s: %w", dir, err)
	}
	defer f.Close()

	_, err = f.ReadDir(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", dir, err)
	}
	return false, nil
}
