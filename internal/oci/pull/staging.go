package pull

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// staging is a temporary directory a component is restored into, beside
// its own, so the component's directory only ever appears whole: commit
// swaps it into place once everything in it is verified, and discard
// removes it otherwise.
type staging struct {
	// dir is the temporary directory.
	dir string
	// destDir is the component's directory, which commit replaces.
	destDir string
}

// writeStaged runs write on a staging directory for destDir, and swaps it
// into place only if write succeeds: destDir is left as it was otherwise.
func writeStaged(destDir string, write func(dir string) error) error {
	stage, err := newStaging(destDir)
	if err != nil {
		return err
	}
	defer stage.discard()

	if err := write(stage.dir); err != nil {
		return err
	}
	return stage.commit()
}

// newStaging creates a staging directory for destDir, beside it.
func newStaging(destDir string) (*staging, error) {
	parent := filepath.Dir(destDir)
	if err := os.MkdirAll(parent, transfer.DirPerm); err != nil {
		return nil, fmt.Errorf("create %s: %w", parent, err)
	}
	dir, err := os.MkdirTemp(parent, ".pull-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	stage := staging{
		dir:     dir,
		destDir: destDir,
	}
	return &stage, nil
}

// commit replaces destDir, if it exists, with the staging directory.
func (s *staging) commit() error {
	if err := os.RemoveAll(s.destDir); err != nil {
		return fmt.Errorf("remove existing %s: %w", s.destDir, err)
	}
	if err := os.Rename(s.dir, s.destDir); err != nil {
		return fmt.Errorf("rename to %s: %w", s.destDir, err)
	}
	return nil
}

// discard removes the staging directory, unless commit moved it.
func (s *staging) discard() {
	os.RemoveAll(s.dir)
}

// checkOutputDir fails unless dir is missing or a directory, and, unless
// replace is set, an empty one.
func checkOutputDir(dir string, replace bool) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if replace {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("check %s: %w", dir, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty", dir)
	}
	return nil
}

// writeInto runs write on a staging directory inside dir, then moves what
// it wrote up into dir. dir must be missing or empty, unless replace is
// set: then what it held is removed, but only once write has succeeded,
// so a failed write leaves it as it was.
//
// Unlike writeStaged it can't swap a whole directory into place, because
// dir may be a mount point, such as a volume in a container, which can't
// be replaced; staging inside it keeps the moves on one file system.
func writeInto(dir string, replace bool, write func(stageDir string) error) (err error) {
	if err := checkOutputDir(dir, replace); err != nil {
		return err
	}
	_, statErr := os.Stat(dir)
	created := os.IsNotExist(statErr)
	if err := os.MkdirAll(dir, transfer.DirPerm); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	var moved []string
	stageDir, err := os.MkdirTemp(dir, ".pull-*")
	if err != nil {
		if created {
			os.Remove(dir)
		}
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		os.RemoveAll(stageDir)
		if err == nil {
			return
		}
		for _, path := range moved {
			os.RemoveAll(path)
		}
		if created {
			os.Remove(dir)
		}
	}()

	if err := write(stageDir); err != nil {
		return err
	}
	if replace {
		if err := removeAllBut(dir, filepath.Base(stageDir)); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return fmt.Errorf("list %s: %w", stageDir, err)
	}
	for _, entry := range entries {
		destination := filepath.Join(dir, entry.Name())
		if err := os.Rename(filepath.Join(stageDir, entry.Name()), destination); err != nil {
			return fmt.Errorf("move %s into %s: %w", entry.Name(), dir, err)
		}
		moved = append(moved, destination)
	}
	return nil
}

// removeAllBut removes everything in dir except the entry named keep.
func removeAllBut(dir, keep string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("list %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.Name() == keep {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("remove %s: %w", entry.Name(), err)
		}
	}
	return nil
}
