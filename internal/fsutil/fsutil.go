// Package fsutil holds small filesystem helpers shared across bomify's
// data directory code.
package fsutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path via a temp file renamed into
// place, so a reader never sees a partial file. path's directory is
// created if needed, and the file ends up 0644, like the rest of the
// data directory.
func WriteFileAtomic(path string, data []byte) error {
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
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
