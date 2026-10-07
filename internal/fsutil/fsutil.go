// Package fsutil holds small filesystem helpers shared across bomify,
// mostly for its data directory.
package fsutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// WriteTemp writes data to a new file in the OS temp directory, named
// by pattern as os.CreateTemp names it, and returns its path, which the
// caller must remove. Nothing is left behind if it fails.
func WriteTemp(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write %s: %w", f.Name(), err)
	}
	return f.Name(), nil
}

// WriteFileAtomic writes data to path atomically (see WriteAtomic).
func WriteFileAtomic(path string, data []byte) error {
	return WriteAtomic(path, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// WriteAtomic writes path with write, via a temp file renamed into
// place, so a reader never sees a partial file, and a failed write
// leaves any existing path untouched. path's directory is created if
// needed, and the file ends up 0644, like the rest of the data
// directory. Unlike WriteFileAtomic, it streams, for files too large to
// hold in memory.
func WriteAtomic(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	// Each failure closes tmp before returning, so the deferred Remove can
	// delete it, which Windows can't do to an open file.
	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	// CreateTemp makes the file 0600; data directory files are 0644.
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// WriteJSON writes v to path as indented JSON, atomically (see
// WriteFileAtomic). HTML escaping is disabled: json.Marshal's default
// would otherwise mangle purl query strings ("...&tag=..." becomes
// "...&tag=...").
func WriteJSON(path string, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	return WriteFileAtomic(path, buf.Bytes())
}

// ReadJSON parses the JSON file at path into v. A missing file is not an
// error: v is left untouched, so callers pre-set it to their empty value.
func ReadJSON(path string, v any) error {
	return readJSON(path, v, false)
}

// ReadJSONStrict is ReadJSON, but fails on a field v has no place for,
// so a misspelled field, or one a newer bomify added, is an error rather
// than silently ignored.
func ReadJSONStrict(path string, v any) error {
	return readJSON(path, v, true)
}

func readJSON(path string, v any, strict bool) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if decoder.More() {
		return fmt.Errorf("parse %s: unexpected data after the JSON value", path)
	}
	return nil
}
