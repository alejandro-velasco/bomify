package transfer

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
)

// symlink makes link point to target, skipping the test where the OS
// won't allow it, as on Windows without Developer Mode.
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("can't create symlinks here: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// tarEntry is one entry of a tar buildOrderedTar writes: a symlink to
// link if set, else a file of content.
type tarEntry struct {
	name    string
	link    string
	content string
}

func buildOrderedTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, entry := range entries {
		hdr := &tar.Header{
			Name:     entry.name,
			Mode:     0o644,
			Typeflag: tar.TypeReg,
			Size:     int64(len(entry.content)),
		}
		if entry.link != "" {
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = entry.link
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestWriteTarThenExtractTarKeepsSymlinks(t *testing.T) {
	srcDir := t.TempDir()
	writeFile(t, filepath.Join(srcDir, "lib", "real.txt"), "real")
	symlink(t, filepath.Join("lib", "real.txt"), filepath.Join(srcDir, "file-link"))
	symlink(t, "lib", filepath.Join(srcDir, "dir-link"))
	symlink(t, filepath.Join("..", "real.txt"), filepath.Join(srcDir, "lib", "sub", "up-link"))

	var buf bytes.Buffer
	if err := WriteTar(srcDir, &buf); err != nil {
		t.Fatalf("WriteTar() error = %v", err)
	}
	destDir := t.TempDir()
	if err := ExtractTar(tar.NewReader(&buf), destDir); err != nil {
		t.Fatalf("ExtractTar() error = %v", err)
	}

	links := map[string]string{
		"file-link":       "lib/real.txt",
		"dir-link":        "lib",
		"lib/sub/up-link": "../real.txt",
	}
	for link, want := range links {
		got, err := os.Readlink(filepath.Join(destDir, filepath.FromSlash(link)))
		if err != nil || filepath.ToSlash(got) != want {
			t.Errorf("%s points to %q, %v; want %q", link, got, err, want)
		}
	}
	data, err := os.ReadFile(filepath.Join(destDir, "dir-link", "real.txt"))
	if err != nil || string(data) != "real" {
		t.Errorf("dir-link/real.txt = %q, %v; want %q", data, err, "real")
	}
}

func TestTarFilesRejectsBadSymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeFile(t, outside, "secret")

	tests := map[string][]tarEntry{
		"escaping":  {{name: "link", link: filepath.Join("..", "outside.txt")}},
		"absolute":  {{name: "link", link: outside}},
		"dangling":  {{name: "link", link: "missing.txt"}},
		"via links": {{name: "here", link: "."}, {name: "link", link: filepath.Join("here", "..", "outside.txt")}},
	}
	for name, links := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, link := range links {
				symlink(t, link.link, filepath.Join(dir, link.name))
			}
			if _, err := TarFiles(dir); err == nil {
				t.Error("TarFiles() succeeded, want an error")
			}
		})
	}
}

func TestExtractTarRejectsBadSymlinks(t *testing.T) {
	symlink(t, "target", filepath.Join(t.TempDir(), "probe"))

	tests := map[string][]tarEntry{
		"escaping": {{name: "link", link: "../escaped.txt"}},
		"absolute": {{name: "link", link: "/etc/passwd"}},
		"dangling": {{name: "link", link: "missing.txt"}},
		"via links": {
			{name: "here", link: "."},
			{name: "link", link: "here/../escaped.txt"},
		},
		"written through": {
			{name: "up", link: ".."},
			{name: "up/escaped.txt", content: "malicious content"},
		},
	}
	extracts := map[string]func(*tar.Reader, string) error{
		"ExtractTar": ExtractTar,
		// It leaves checking its links to its caller, but nothing may
		// still be written through one.
		"ExtractTarExclusive": func(tr *tar.Reader, destDir string) error {
			if err := ExtractTarExclusive(tr, destDir); err != nil {
				return err
			}
			return fsutil.CheckSymlinks(destDir)
		},
	}
	for extractName, extract := range extracts {
		for name, entries := range tests {
			t.Run(extractName+"/"+name, func(t *testing.T) {
				parent := t.TempDir()
				destDir := filepath.Join(parent, "dest")
				data := buildOrderedTar(t, entries)

				if err := extract(tar.NewReader(bytes.NewReader(data)), destDir); err == nil {
					t.Error("extract succeeded, want an error")
				}
				if _, err := os.Stat(filepath.Join(parent, "escaped.txt")); err == nil {
					t.Error("a file was written outside the destination")
				}
			})
		}
	}
}
