package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic writes data to path via a temp file renamed into
// place, so a reader never sees a partial file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	// CreateTemp makes the file 0600; data directory files are 0644.
	_, writeErr := tmp.Write(data)
	chmodErr := tmp.Chmod(0o644)
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, chmodErr, closeErr); err != nil {
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
