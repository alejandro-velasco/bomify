package fsutil

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTemp(t *testing.T) {
	path, err := WriteTemp("bomify-test-*.json", []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("WriteTemp: %v", err)
	}
	defer os.Remove(path)

	if !strings.HasPrefix(filepath.Base(path), "bomify-test-") || !strings.HasSuffix(path, ".json") {
		t.Errorf("path = %q, want it named by the pattern", path)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != `{"a":1}` {
		t.Errorf("contents = %q, %v; want the data", data, err)
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "out.tar")

	write := func(w io.Writer) error {
		_, err := io.WriteString(w, "first")
		return err
	}
	if err := WriteAtomic(path, write); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "first" {
		t.Errorf("contents = %q, %v; want what write wrote", data, err)
	}

	// A failed write returns its error and leaves the file as it was.
	failing := func(w io.Writer) error {
		io.WriteString(w, "partial")
		return errors.New("boom")
	}
	if err := WriteAtomic(path, failing); err == nil || err.Error() != "boom" {
		t.Errorf("WriteAtomic of a failing write = %v, want its error", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "first" {
		t.Errorf("contents after a failed write = %q, want the original", data)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("directory has %d entries, want no temp file left behind", len(entries))
	}
}
