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

func TestReadJSONStrict(t *testing.T) {
	type record struct {
		Name string `json:"name"`
	}
	path := filepath.Join(t.TempDir(), "record.json")

	if err := os.WriteFile(path, []byte(`{"name":"a","extra":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var lenient record
	if err := ReadJSON(path, &lenient); err != nil || lenient.Name != "a" {
		t.Errorf("ReadJSON = %+v, %v; want the unknown field ignored", lenient, err)
	}
	var strict record
	if err := ReadJSONStrict(path, &strict); err == nil || !strings.Contains(err.Error(), `unknown field "extra"`) {
		t.Errorf("ReadJSONStrict = %v, want the unknown field rejected", err)
	}

	if err := os.WriteFile(path, []byte(`{"name":"a"}{"name":"b"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONStrict(path, &strict); err == nil {
		t.Error("ReadJSONStrict accepted data after the JSON value")
	}

	missing := record{
		Name: "unchanged",
	}
	if err := ReadJSONStrict(filepath.Join(t.TempDir(), "missing.json"), &missing); err != nil || missing.Name != "unchanged" {
		t.Errorf("ReadJSONStrict on a missing file = %+v, %v; want it left untouched", missing, err)
	}
}
