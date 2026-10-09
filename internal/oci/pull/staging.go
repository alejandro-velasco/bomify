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
