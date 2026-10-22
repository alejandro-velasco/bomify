//go:build !windows

package transfer

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestTarFilesRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Skipf("can't make a FIFO here: %v", err)
	}

	_, err := TarFiles(dir)

	wantError(t, err, "neither a regular file nor a symlink")
}
