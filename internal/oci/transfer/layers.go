package transfer

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
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

// IsSafePath reports whether path, "/"-separated and from the network,
// names a file inside the directory it's joined to: relative, with no
// ".." segment, no backslash, and no NUL byte.
func IsSafePath(path string) bool {
	if path == "" || strings.ContainsAny(path, "\\\x00") {
		return false
	}
	return filepath.IsLocal(filepath.FromSlash(path))
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
