package transfer

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
)

// FilePartMediaType identifies one part of a large file of a component:
// the file's raw bytes from its AnnotationFileOffset, of the layer's own
// size. A file at least LargeFileSize long is pushed this way, in parts of
// at most MaxLayerSize, rather than in its component's tar layers, so no
// layer outgrows a registry's limit, and an unchanged file is the same
// blob in every package. Pull writes each part into the file
// AnnotationFilePath names, inside its component's directory.
const FilePartMediaType = "application/vnd.bomify.component.file.v1"

// Annotations of a FilePartMediaType layer, besides AnnotationPurl.
const (
	// AnnotationFilePath is the file's "/"-separated path inside its
	// component's directory.
	AnnotationFilePath = "land.bomify.file.path"
	// AnnotationFileMode is the file's permission bits, in octal, e.g.
	// "0755".
	AnnotationFileMode = "land.bomify.file.mode"
	// AnnotationFileSize is the whole file's size in bytes, so pull can
	// tell its parts cover it exactly.
	AnnotationFileSize = "land.bomify.file.size"
	// AnnotationFileOffset is where in the file the part starts.
	AnnotationFileOffset = "land.bomify.file.offset"
)

// LargeFileSize and MaxLayerSize shape a component's layers (see
// FilePartMediaType): a file at least LargeFileSize long gets its own
// layers, and no layer is larger than MaxLayerSize, safely under the
// 10 GB per layer GHCR and Docker Hub allow. Variables so tests can make
// them small.
var (
	LargeFileSize int64 = 64 << 20
	MaxLayerSize  int64 = 4 << 30
)

// IsSafePath reports whether path, "/"-separated and from the network,
// names a file inside the directory it's joined to: relative, with no
// ".." segment and no backslash.
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

// TarSize returns how much a file of size adds to a tar stream: its
// header and its content padded to the 512-byte block, not counting the
// longer headers a long name needs.
func TarSize(size int64) int64 {
	return 512 + (size+511)/512*512
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

// FilePart is what a file part layer's annotations say (see
// FilePartMediaType): which file the part is of, its mode and size, and
// where in it the part starts. Annotations writes them, and
// ParseFilePart reads them back.
type FilePart struct {
	// Path is the file's "/"-separated path in its component's directory.
	Path     string
	Mode     fs.FileMode
	FileSize int64
	Offset   int64
}

// Annotations returns p as a file part layer's annotations, with its
// component's purl.
func (p FilePart) Annotations(purl string) map[string]string {
	annotations := map[string]string{
		AnnotationPurl:       purl,
		AnnotationFilePath:   p.Path,
		AnnotationFileMode:   fmt.Sprintf("%04o", p.Mode.Perm()),
		AnnotationFileSize:   strconv.FormatInt(p.FileSize, 10),
		AnnotationFileOffset: strconv.FormatInt(p.Offset, 10),
	}
	return annotations
}

// ParseFilePart reads a file part layer's annotations, which come from
// the network: the path must stay inside its component (see IsSafePath),
// the mode be permission bits, and the size and offset non-negative.
func ParseFilePart(annotations map[string]string) (FilePart, error) {
	path := annotations[AnnotationFilePath]
	if !IsSafePath(path) {
		return FilePart{}, fmt.Errorf("file %q is outside its component", path)
	}
	mode, err := parseFileMode(annotations[AnnotationFileMode])
	if err != nil {
		return FilePart{}, err
	}
	fileSize, err := parseSize(annotations[AnnotationFileSize])
	if err != nil {
		return FilePart{}, fmt.Errorf("file size: %w", err)
	}
	offset, err := parseSize(annotations[AnnotationFileOffset])
	if err != nil {
		return FilePart{}, fmt.Errorf("offset: %w", err)
	}

	part := FilePart{
		Path:     path,
		Mode:     mode,
		FileSize: fileSize,
		Offset:   offset,
	}
	return part, nil
}

// parseSize parses an AnnotationFileSize or AnnotationFileOffset value, as
// a non-negative int64: a file's sizes and offsets outgrow a 32-bit int.
func parseSize(value string) (int64, error) {
	size, err := strconv.ParseInt(value, 10, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("%q isn't a size", value)
	}
	return size, nil
}

// parseFileMode parses an AnnotationFileMode value.
func parseFileMode(value string) (fs.FileMode, error) {
	var mode uint32
	if _, err := fmt.Sscanf(value, "%o", &mode); err != nil || mode > 0o777 {
		return 0, fmt.Errorf("invalid file mode %q", value)
	}
	return fs.FileMode(mode), nil
}
