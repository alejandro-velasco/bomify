package fsutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// CheckSymlinks fails unless every symlink under dir resolves, through
// any other links on the way, to something inside dir: so nothing that
// reads dir later is led outside it. A link must be relative, and may not
// dangle.
func CheckSymlinks(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type() != fs.ModeSymlink {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		return checkSymlink(root, relative)
	})
}

// checkSymlink checks the symlink name, relative to root, as
// CheckSymlinks does: root follows links only while they stay inside it.
func checkSymlink(root *os.Root, name string) error {
	if _, err := root.Stat(name); err != nil {
		return fmt.Errorf("symlink %s doesn't resolve inside its directory: %w", filepath.ToSlash(name), err)
	}
	return nil
}
