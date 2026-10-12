package transfer

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
)

// FileMediaType identifies a large file of a component: a layer that is
// the file's own bytes. A file at least LargeFileSize long is pushed this
// way, rather than in its component's tar layers, so an unchanged file is
// the same blob in every package, and tools that don't know bomify can
// write it out. It's never split, so a file past a registry's layer limit
// (10 GB on GHCR and Docker Hub) can't be pushed there. Pull writes it to
// the path AnnotationFilePath names, inside its component's directory.
const FileMediaType = "application/vnd.bomify.component.file.v1"

// Annotations of a FileMediaType layer, besides AnnotationPurl.
const (
	// AnnotationFilePath is the file's "/"-separated path inside its
	// component's directory.
	AnnotationFilePath = "land.bomify.file.path"
	// AnnotationFileMode is the file's permission bits, in octal, e.g.
	// "0755".
	AnnotationFileMode = "land.bomify.file.mode"
)

// LargeFileSize and MaxTarSize shape a component's layers: a file at
// least LargeFileSize long is a layer of its own (see FileMediaType), and
// the rest go in tars of at most MaxTarSize. Variables so tests can make
// them small.
var (
	LargeFileSize int64 = 64 << 20
	MaxTarSize    int64 = 4 << 30
)

// ceilDiv divides dividend by divisor, rounding up where integer division
// rounds down: adding divisor-1 first carries any remainder of 1 to
// divisor-1 into one more, while an exact multiple doesn't reach the
// next.
func ceilDiv(dividend, divisor int64) int64 {
	return (dividend + divisor - 1) / divisor
}

// IsSafePath reports whether path, "/"-separated and from the network,
// names a file inside the directory it's joined to: relative, with no
// ".." segment, no backslash, and no NUL byte.
func IsSafePath(path string) bool {
	if path == "" || strings.ContainsAny(path, "\\\x00") {
		return false
	}
	return filepath.IsLocal(filepath.FromSlash(path))
}

// TarFile is one file WriteTar archives from a directory.
type TarFile struct {
	// Path is its "/"-separated path, relative to the directory.
	Path string
	Size int64
	// Mode is its mode, not following a symlink.
	Mode fs.FileMode
}

// TarFiles returns every file WriteTar archives from dir, in its order:
// its regular files and symlinks. It fails on anything else, or on a
// symlink that doesn't resolve inside dir (see fsutil.CheckSymlinks),
// which pull would refuse.
func TarFiles(dir string) ([]TarFile, error) {
	var files []TarFile
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && info.Mode().Type() != fs.ModeSymlink {
			return fmt.Errorf("%s is neither a regular file nor a symlink", filepath.ToSlash(relative))
		}
		file := TarFile{
			Path: filepath.ToSlash(relative),
			Size: info.Size(),
			Mode: info.Mode(),
		}
		files = append(files, file)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := fsutil.CheckSymlinks(dir); err != nil {
		return nil, err
	}
	return files, nil
}

// tarBlockSize is the tar format's block size: an entry's header takes
// one block, and its content is padded to a whole number of blocks.
const tarBlockSize = 512

// TarSize returns how much a file of size adds to a tar stream: its
// header block and its content padded to whole blocks, a partly filled
// last block taking a whole one (see ceilDiv), not counting the longer
// headers a long name needs.
func TarSize(size int64) int64 {
	header := int64(tarBlockSize)
	blocks := ceilDiv(size, tarBlockSize)
	return header + blocks*tarBlockSize
}

// WriteTarFiles archives files, some of TarFiles(dir), into w, as
// WriteTar does all of dir's.
func WriteTarFiles(dir string, files []TarFile, w io.Writer) error {
	tw := tar.NewWriter(w)
	for _, file := range files {
		if err := writeTarEntry(tw, dir, file.Path); err != nil {
			return err
		}
	}
	return tw.Close()
}

func writeTarEntry(tw *tar.Writer, dir, path string) error {
	full := filepath.Join(dir, filepath.FromSlash(path))
	info, err := os.Lstat(full)
	if err != nil {
		return err
	}
	var link string
	if info.Mode().Type() == fs.ModeSymlink {
		target, err := os.Readlink(full)
		if err != nil {
			return err
		}
		link = filepath.ToSlash(target)
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is neither a regular file nor a symlink", path)
	}
	hdr, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return err
	}
	hdr.Name = path
	normalizeHeader(hdr)
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	// A symlink is its header alone.
	if link != "" {
		return nil
	}

	f, err := os.Open(full)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// ExtractTarExclusive is ExtractTar, but fails on an entry naming a file
// that already exists, rather than replacing it: a component's layers
// each hold different files, so no layer may overwrite another's. It
// leaves its symlinks unchecked, since one may point to a file another
// layer holds: check them with fsutil.CheckSymlinks once every layer
// is in.
func ExtractTarExclusive(tr *tar.Reader, destDir string) error {
	return extractTar(tr, destDir, os.O_EXCL)
}

// File is what a file layer's annotations say (see FileMediaType): the
// file's path and mode. Annotations writes them, and ParseFile reads them
// back.
type File struct {
	// Path is the file's "/"-separated path in its component's directory.
	Path string
	Mode fs.FileMode
}

// Annotations returns f as a file layer's annotations, with its
// component's purl.
func (f File) Annotations(purl string) map[string]string {
	annotations := map[string]string{
		AnnotationPurl:     purl,
		AnnotationFilePath: f.Path,
		AnnotationFileMode: fmt.Sprintf("%04o", f.Mode.Perm()),
	}
	return annotations
}

// ParseFile reads a file layer's annotations, which come from the network:
// the path must stay inside its component (see IsSafePath), and the mode
// be permission bits.
func ParseFile(annotations map[string]string) (File, error) {
	path := annotations[AnnotationFilePath]
	if !IsSafePath(path) {
		return File{}, fmt.Errorf("file %q is outside its component", path)
	}
	mode, err := parseFileMode(annotations[AnnotationFileMode])
	if err != nil {
		return File{}, err
	}

	file := File{
		Path: path,
		Mode: mode,
	}
	return file, nil
}

// parseFileMode parses an AnnotationFileMode value.
func parseFileMode(value string) (fs.FileMode, error) {
	var mode uint32
	if _, err := fmt.Sscanf(value, "%o", &mode); err != nil || mode > uint32(fs.ModePerm) {
		return 0, fmt.Errorf("invalid file mode %q", value)
	}
	return fs.FileMode(mode), nil
}
