package ocitransfer

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func buildTar(t *testing.T, entries map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header for %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("write content for %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtractTarRejectsPathTraversal(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{"parent traversal", "../escaped.txt"},
		{"nested parent traversal", "sub/../../escaped.txt"},
		{"absolute path", "/etc/escaped.txt"},
		{"bare parent", ".."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildTar(t, map[string]string{tt.entry: "malicious content"})
			destDir := t.TempDir()

			err := ExtractTar(tar.NewReader(bytes.NewReader(data)), destDir)
			if err == nil {
				t.Fatalf("ExtractTar() with entry %q: expected error, got nil", tt.entry)
			}

			// Nothing should have been written outside destDir: confirm
			// the parent of destDir (where an escape would land) gained
			// no new file.
			parent := filepath.Dir(destDir)
			escapedPath := filepath.Join(parent, "escaped.txt")
			if _, err := os.Stat(escapedPath); err == nil {
				t.Errorf("ExtractTar() with entry %q escaped to %s", tt.entry, escapedPath)
			}
		})
	}
}

func TestWriteTarThenExtractTarRoundTrips(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "b.txt"), []byte("bbb"), 0o644); err != nil {
		t.Fatalf("write sub/b.txt: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteTar(srcDir, &buf); err != nil {
		t.Fatalf("WriteTar() error = %v", err)
	}

	destDir := t.TempDir()
	if err := ExtractTar(tar.NewReader(&buf), destDir); err != nil {
		t.Fatalf("ExtractTar() error = %v", err)
	}

	gotA, err := os.ReadFile(filepath.Join(destDir, "a.txt"))
	if err != nil {
		t.Fatalf("read a.txt: %v", err)
	}
	if string(gotA) != "aaa" {
		t.Errorf("a.txt = %q, want %q", gotA, "aaa")
	}

	gotB, err := os.ReadFile(filepath.Join(destDir, "sub", "b.txt"))
	if err != nil {
		t.Fatalf("read sub/b.txt: %v", err)
	}
	if string(gotB) != "bbb" {
		t.Errorf("sub/b.txt = %q, want %q", gotB, "bbb")
	}
}
