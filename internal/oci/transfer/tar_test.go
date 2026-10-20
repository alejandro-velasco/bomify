package transfer

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestWriteTarNormalizesHeaderMetadata covers normalizeHeader directly:
// a file's mtime and uid/gid — incidental local filesystem state, not
// part of its actual content — never make it into the tar WriteTar
// produces.
func TestWriteTarNormalizesHeaderMetadata(t *testing.T) {
	srcDir := t.TempDir()
	path := filepath.Join(srcDir, "a.txt")
	if err := os.WriteFile(path, []byte("aaa"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	oldTime := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteTar(srcDir, &buf); err != nil {
		t.Fatalf("WriteTar() error = %v", err)
	}

	hdr, err := tar.NewReader(&buf).Next()
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if got := hdr.ModTime.Unix(); got != 0 {
		t.Errorf("ModTime = %v (unix %d), want the Unix epoch", hdr.ModTime, got)
	}
	if hdr.Uid != 0 || hdr.Gid != 0 {
		t.Errorf("Uid/Gid = %d/%d, want 0/0", hdr.Uid, hdr.Gid)
	}
}

// TestWriteTarIsStableAcrossExtractRoundTrip covers the actual bug this
// normalization fixes: re-tarring a layer bomify itself just pulled
// must reproduce the exact same bytes — and so the same digest "bomify
// push" computes over them — as the original tar, even though
// ExtractTar (deliberately) gives every file it writes a fresh mtime
// rather than restoring whatever mtime the source tar's header carried.
// Without normalization, an unrelated "bomify rmp" + "bomify pull" in
// between two pushes of the same unchanged component would make the
// second push re-upload it under a brand new digest.
func TestWriteTarIsStableAcrossExtractRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	path := filepath.Join(srcDir, "a.txt")
	if err := os.WriteFile(path, []byte("aaa"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	// A deliberately unusual mtime, standing in for whatever a component
	// plugin happened to leave on a freshly built/pulled file.
	oldTime := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	var firstTar bytes.Buffer
	if err := WriteTar(srcDir, &firstTar); err != nil {
		t.Fatalf("WriteTar() (first) error = %v", err)
	}

	destDir := t.TempDir()
	if err := ExtractTar(tar.NewReader(bytes.NewReader(firstTar.Bytes())), destDir); err != nil {
		t.Fatalf("ExtractTar() error = %v", err)
	}

	// Confirm the test actually exercises the scenario it claims to:
	// the extracted file must NOT have kept the original mtime, or this
	// test would pass for the wrong reason.
	info, err := os.Stat(filepath.Join(destDir, "a.txt"))
	if err != nil {
		t.Fatalf("stat extracted file: %v", err)
	}
	if info.ModTime().Equal(oldTime) {
		t.Fatal("test setup invalid: extracted file kept the original mtime instead of getting a fresh one")
	}

	var secondTar bytes.Buffer
	if err := WriteTar(destDir, &secondTar); err != nil {
		t.Fatalf("WriteTar() (second) error = %v", err)
	}

	first := sha256.Sum256(firstTar.Bytes())
	second := sha256.Sum256(secondTar.Bytes())
	if first != second {
		t.Errorf("tar digest changed across an extract round trip for identical content: %x != %x", first, second)
	}
}
