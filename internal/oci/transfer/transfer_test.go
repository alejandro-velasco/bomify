package transfer

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"maps"
	"os"
	"path/filepath"
	"strings"
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

func TestParseSize(t *testing.T) {
	for value, want := range map[string]int64{"0": 0, "4294967296": 4 << 30, "10737418240": 10 << 30} {
		if got, err := parseSize(value); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", value, got, err, want)
		}
	}
	for _, value := range []string{"", "-1", "1.5", "0x10", "ten"} {
		if _, err := parseSize(value); err == nil {
			t.Errorf("parseSize(%q) succeeded", value)
		}
	}
}

func TestPartLabel(t *testing.T) {
	purl := "pkg:huggingface/org/model@abc"
	if got, want := PartLabel(purl, "model.gguf", 2, 3), "model.gguf 2/3 "+purl; got != want {
		t.Errorf("PartLabel = %q, want %q", got, want)
	}
	// A file in one part isn't numbered.
	if got, want := PartLabel(purl, "weights.bin", 1, 1), "weights.bin "+purl; got != want {
		t.Errorf("PartLabel = %q, want %q", got, want)
	}
}

// TestFilePartRoundTrip pins the file part format: ParseFilePart reads
// back exactly what Annotations writes.
func TestFilePartRoundTrip(t *testing.T) {
	part := FilePart{
		Path:     "dir/model.gguf",
		Mode:     0o755,
		FileSize: 10 << 30,
		Offset:   4 << 30,
	}
	annotations := part.Annotations("pkg:huggingface/org/model@abc")
	if got := annotations[AnnotationPurl]; got != "pkg:huggingface/org/model@abc" {
		t.Errorf("purl annotation = %q", got)
	}

	parsed, err := ParseFilePart(annotations)
	if err != nil {
		t.Fatalf("ParseFilePart: %v", err)
	}
	if parsed != part {
		t.Errorf("ParseFilePart = %+v, want %+v", parsed, part)
	}
}

func TestParseFilePartRejects(t *testing.T) {
	valid := FilePart{Path: "f", Mode: 0o644, FileSize: 3}.Annotations("p")
	for name, tc := range map[string]struct {
		key, value, want string
	}{
		"escaping path": {AnnotationFilePath, "../f", "outside its component"},
		"bad mode":      {AnnotationFileMode, "rwx", "invalid file mode"},
		"mode too wide": {AnnotationFileMode, "4755", "invalid file mode"},
		"bad size":      {AnnotationFileSize, "-1", "file size"},
		"bad offset":    {AnnotationFileOffset, "x", "offset"},
	} {
		annotations := maps.Clone(valid)
		annotations[tc.key] = tc.value
		if _, err := ParseFilePart(annotations); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ParseFilePart = %v, want an error containing %q", name, err, tc.want)
		}
	}
}
