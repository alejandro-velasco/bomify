package fsutil

import (
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
