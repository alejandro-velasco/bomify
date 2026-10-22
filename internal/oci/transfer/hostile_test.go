package transfer

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Tests of what bomify does with names and archives from whoever
// published a package, which it can't trust.

func TestIsSafeFilename(t *testing.T) {
	for name, want := range map[string]bool{
		"grype":                                 true,
		"trivy-0.58":                            true,
		"scanner_v2":                            true,
		"résumé":                                true,
		"console":                               true,
		"COM10":                                 true,
		".hidden":                               true,
		"":                                      false,
		".":                                     false,
		"..":                                    false,
		"../grype":                              false,
		"dir/grype":                             false,
		"/etc/passwd":                           false,
		`dir\grype`:                             false,
		`C:\grype`:                              false,
		"C:grype":                               false,
		"gr*pe":                                 false,
		"gr?pe":                                 false,
		`gr"pe`:                                 false,
		"gr<pe":                                 false,
		"gr>pe":                                 false,
		"gr|pe":                                 false,
		"grype\x00":                             false,
		"gr\x00ype":                             false,
		"grype\n":                               false,
		"gr\type":                               false,
		"grype\x7f":                             false,
		"grype.":                                false,
		"grype ":                                false,
		"\xff":                                  false,
		"CON":                                   false,
		"con":                                   false,
		"nul.json":                              false,
		"Aux.tar.gz":                            false,
		"LPT1":                                  false,
		"COM\u00b9":                             false,
		"PRN .txt":                              false,
		"conout$":                               false,
		strings.Repeat("a", maxFilenameBytes):   true,
		strings.Repeat("a", maxFilenameBytes+1): false,
	} {
		if got := IsSafeFilename(name); got != want {
			t.Errorf("IsSafeFilename(%q) = %v, want %v", name, got, want)
		}
	}
}

// FuzzIsSafeFilename checks that a name IsSafeFilename accepts names
// exactly one file, inside the directory it's created in, with a suffix
// such as a report's.
func FuzzIsSafeFilename(f *testing.F) {
	for _, seed := range []string{"grype", "..", "a/b", `a\b`, "CON", "nul.json", "a\x00", "a.", "\xff", "résumé"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if !IsSafeFilename(name) {
			return
		}
		if !filepath.IsLocal(name) || filepath.Base(name) != name {
			t.Fatalf("IsSafeFilename(%q) accepted a name that isn't one local path component", name)
		}

		dir := t.TempDir()
		file := name + ".json"
		if err := os.WriteFile(filepath.Join(dir, file), []byte("{}"), 0o644); err != nil {
			t.Fatalf("IsSafeFilename(%q) accepted a name that can't be created: %v", name, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || entries[0].Name() != file {
			t.Fatalf("creating %q made %v, want just that file", file, entries)
		}
	})
}

// extractInto extracts data into a "dest" directory of a fresh parent,
// returning ExtractTar's error and the parent, where nothing but dest
// may appear.
func extractInto(t *testing.T, data []byte) (string, error) {
	t.Helper()
	parent := t.TempDir()
	err := ExtractTar(tar.NewReader(bytes.NewReader(data)), filepath.Join(parent, "dest"))
	return parent, err
}

// assertOnlyDest fails t if parent holds anything but "dest".
func assertOnlyDest(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "dest" {
			t.Errorf("extraction wrote %s outside its destination", entry.Name())
		}
	}
}

// headerTar is a tar of hdrs, each followed by its Size in "x"s.
func headerTar(t testing.TB, hdrs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, hdr := range hdrs {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(bytes.Repeat([]byte("x"), int(hdr.Size))); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractTarSkipsHardLinksAndSpecialFiles covers entries WriteTar
// never writes: they're skipped, never recreated, wherever they point.
func TestExtractTarSkipsHardLinksAndSpecialFiles(t *testing.T) {
	for name, hdr := range map[string]*tar.Header{
		"hard link outside":  {Name: "link", Typeflag: tar.TypeLink, Linkname: "../escaped.txt"},
		"hard link absolute": {Name: "link", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"},
		"hard link inside":   {Name: "link", Typeflag: tar.TypeLink, Linkname: "file.txt"},
		"character device":   {Name: "link", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3},
		"block device":       {Name: "link", Typeflag: tar.TypeBlock, Devmajor: 8},
		"fifo":               {Name: "link", Typeflag: tar.TypeFifo},
	} {
		t.Run(name, func(t *testing.T) {
			file := &tar.Header{Name: "file.txt", Mode: 0o644, Typeflag: tar.TypeReg, Size: 4}
			hdr.Mode = 0o644

			parent, err := extractInto(t, headerTar(t, file, hdr))

			if err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(parent, "dest", "link")); !os.IsNotExist(err) {
				t.Errorf("the entry was recreated: %v", err)
			}
			assertOnlyDest(t, parent)
		})
	}
}

func TestExtractTarRejectsEscapingDirectories(t *testing.T) {
	for _, name := range []string{"../escaped", "/escaped", "dir/../../escaped"} {
		parent, err := extractInto(t, headerTar(t, &tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir}))

		if err == nil {
			t.Errorf("ExtractTar of directory %q succeeded, want an error", name)
		}
		assertOnlyDest(t, parent)
	}
}

func TestExtractTarMakesDirectoryEntries(t *testing.T) {
	data := headerTar(t, &tar.Header{Name: "empty/", Mode: 0o755, Typeflag: tar.TypeDir})

	parent, err := extractInto(t, data)

	if err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}
	if info, err := os.Stat(filepath.Join(parent, "dest", "empty")); err != nil || !info.IsDir() {
		t.Errorf("empty/ = %v, %v, want a directory", info, err)
	}
}

// TestExtractTarFailsOnConflictingEntries covers entries that can't all
// be made, such as a file where a later entry needs a directory.
func TestExtractTarFailsOnConflictingEntries(t *testing.T) {
	file := &tar.Header{Name: "file", Mode: 0o644, Typeflag: tar.TypeReg, Size: 1}
	dir := &tar.Header{Name: "dir", Mode: 0o755, Typeflag: tar.TypeDir}
	for name, hdrs := range map[string][]*tar.Header{
		"a directory under a file": {file, {Name: "file/sub", Mode: 0o755, Typeflag: tar.TypeDir}},
		"a file under a file":      {file, {Name: "file/inner", Mode: 0o644, Typeflag: tar.TypeReg, Size: 1}},
		"a symlink under a file":   {file, {Name: "file/link", Typeflag: tar.TypeSymlink, Linkname: "target"}},
		"a file over a directory":  {dir, {Name: "dir", Mode: 0o644, Typeflag: tar.TypeReg, Size: 1}},
		"a symlink over a file":    {file, {Name: "file", Typeflag: tar.TypeSymlink, Linkname: "target"}},
	} {
		t.Run(name, func(t *testing.T) {
			parent, err := extractInto(t, headerTar(t, hdrs...))

			if err == nil {
				t.Error("ExtractTar succeeded, want an error")
			}
			assertOnlyDest(t, parent)
		})
	}
}

func TestExtractTarFailsOnADestinationUnderAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	writeFile(t, file, "content")
	data := headerTar(t, &tar.Header{Name: "f", Mode: 0o644, Typeflag: tar.TypeReg, Size: 1})

	if err := ExtractTar(tar.NewReader(bytes.NewReader(data)), filepath.Join(file, "dest")); err == nil {
		t.Error("ExtractTar under a file succeeded, want an error")
	}
}

func TestExtractTarRejectsBrokenArchives(t *testing.T) {
	whole := headerTar(t, &tar.Header{Name: "file.txt", Mode: 0o644, Typeflag: tar.TypeReg, Size: 2048})
	corrupt := bytes.Clone(whole)
	// The header's checksum field, bytes 148 to 155.
	copy(corrupt[148:156], "0000000\x00")

	for name, data := range map[string][]byte{
		"truncated in a file": whole[:512+100],
		"truncated header":    whole[:200],
		"corrupt header":      corrupt,
	} {
		t.Run(name, func(t *testing.T) {
			parent, err := extractInto(t, data)

			if err == nil {
				t.Error("ExtractTar succeeded, want an error")
			}
			assertOnlyDest(t, parent)
		})
	}
}

// TestExtractTarKeepsTheLastOfADuplicateEntry covers a name the tar has
// twice: the later entry replaces the earlier, as tar does.
func TestExtractTarKeepsTheLastOfADuplicateEntry(t *testing.T) {
	data := buildOrderedTar(t, []tarEntry{
		{name: "file.txt", content: "first, and longer"},
		{name: "file.txt", content: "second"},
	})

	parent, err := extractInto(t, data)

	if err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(parent, "dest", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("file.txt = %q, want the later entry's %q", got, "second")
	}
}

// TestExtractTarDropsSpecialModeBits covers a file asking to be setuid,
// setgid, or sticky: only its permission bits are kept.
func TestExtractTarDropsSpecialModeBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no setuid bit")
	}
	hdr := &tar.Header{Name: "tool", Mode: 0o7755, Typeflag: tar.TypeReg, Size: 4}

	parent, err := extractInto(t, headerTar(t, hdr))

	if err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}
	info, err := os.Stat(filepath.Join(parent, "dest", "tool"))
	if err != nil {
		t.Fatal(err)
	}
	if special := info.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky); special != 0 {
		t.Errorf("mode = %v, want no %v", info.Mode(), special)
	}
}

// FuzzExtractTar checks that no archive, however malformed, makes
// ExtractTar write outside its destination.
func FuzzExtractTar(f *testing.F) {
	seeds := [][]tarEntry{
		{{name: "file.txt", content: "content"}, {name: "dir/nested.txt", content: "nested"}},
		{{name: "../escaped.txt", content: "malicious"}},
		{{name: "up", link: ".."}, {name: "up/escaped.txt", content: "malicious"}},
		{{name: "link", link: "/etc/passwd"}},
		{{name: "file.txt", content: "first"}, {name: "file.txt", link: "../escaped.txt"}},
	}
	for _, seed := range seeds {
		f.Add(buildOrderedTar(f, seed))
	}
	f.Add(headerTar(f, &tar.Header{Name: "link", Typeflag: tar.TypeLink, Linkname: "../escaped.txt"}))
	f.Add(headerTar(f, &tar.Header{Name: "file.txt", Mode: 0o644, Typeflag: tar.TypeReg, Size: 600})[:700])
	f.Add(paxSparseTar(10 << 30))
	f.Add(oldGNUSparseTar(10 << 30))

	f.Fuzz(func(t *testing.T, data []byte) {
		parent, _ := extractInto(t, data)
		assertOnlyDest(t, parent)
	})
}

// TestExtractTarRejectsSparseFiles covers a sparse file declaring 10 GiB
// of holes in a few bytes of tar, which would fill the disk with zeros.
func TestExtractTarRejectsSparseFiles(t *testing.T) {
	for name, data := range map[string][]byte{
		"PAX":     paxSparseTar(10 << 30),
		"old GNU": oldGNUSparseTar(10 << 30),
	} {
		t.Run(name, func(t *testing.T) {
			parent, err := extractInto(t, data)

			if err == nil || !strings.Contains(err.Error(), "sparse") {
				t.Errorf("ExtractTar = %v, want it to refuse a sparse file", err)
			}
			if _, err := os.Stat(filepath.Join(parent, "dest", "big")); !os.IsNotExist(err) {
				t.Errorf("the sparse file was written: %v", err)
			}
		})
	}
}

// paxSparseTar is a tar of one PAX sparse file, "big", of size bytes,
// all hole. archive/tar's writer won't write one, so it's built by hand.
func paxSparseTar(size int64) []byte {
	records := paxRecord("GNU.sparse.major", "1") +
		paxRecord("GNU.sparse.minor", "0") +
		paxRecord("GNU.sparse.name", "big") +
		paxRecord("GNU.sparse.realsize", fmt.Sprint(size))
	// The sparse map, of no data regions, opens the file's content.
	sparseMap := padBlock([]byte("0\n"))

	var data []byte
	data = append(data, rawHeader("PaxHeaders/big", tar.TypeXHeader, int64(len(records)), "ustar\x0000")...)
	data = append(data, padBlock([]byte(records))...)
	data = append(data, rawHeader("big", tar.TypeReg, int64(len(sparseMap)), "ustar\x0000")...)
	data = append(data, sparseMap...)
	return append(data, make([]byte, 1024)...)
}

// oldGNUSparseTar is a tar of one sparse file in the old GNU format,
// "big", of size bytes, all hole.
func oldGNUSparseTar(size int64) []byte {
	block := rawHeader("big", tar.TypeGNUSparse, 0, "ustar  \x00")
	// The real size, after the header's (empty) sparse map.
	copy(block[483:495], fmt.Sprintf("%011o\x00", size))
	setChecksum(block)
	return append(block, make([]byte, 1024)...)
}

// rawHeader is a tar header block for a file name of size bytes, with
// magic, its format's magic and version.
func rawHeader(name string, typeflag byte, size int64, magic string) []byte {
	block := make([]byte, 512)
	copy(block[0:100], name)
	copy(block[100:108], "0000644\x00")
	copy(block[108:116], "0000000\x00")
	copy(block[116:124], "0000000\x00")
	copy(block[124:136], fmt.Sprintf("%011o\x00", size))
	copy(block[136:148], "00000000000\x00")
	block[156] = typeflag
	copy(block[257:265], magic)
	setChecksum(block)
	return block
}

// setChecksum sets a header block's checksum: the sum of its bytes, the
// checksum field counted as spaces.
func setChecksum(block []byte) {
	copy(block[148:156], "        ")
	sum := 0
	for _, b := range block {
		sum += int(b)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

// paxRecord is one PAX record, "<length> <key>=<value>\n", its length
// counting itself.
func paxRecord(key, value string) string {
	body := " " + key + "=" + value + "\n"
	length := len(body)
	for {
		record := fmt.Sprintf("%d%s", length, body)
		if len(record) == length {
			return record
		}
		length = len(record)
	}
}

// padBlock pads b with zeros to a whole number of tar blocks.
func padBlock(b []byte) []byte {
	if rest := len(b) % 512; rest != 0 {
		b = append(b, make([]byte, 512-rest)...)
	}
	return b
}
