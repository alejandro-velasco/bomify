package transfer

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
)

// WriteTar archives every regular file under dir into w as a tar stream,
// with paths relative to dir. It never writes explicit directory entries:
// a tar reader reconstructs a file's parent directories from its path
// alone, so those would be redundant.
//
// Every header is normalized (see normalizeHeader) before it's written,
// so the resulting tar depends only on the archived files' names, modes,
// and content, never on incidental local filesystem metadata, which
// ExtractTar (deliberately, see its own doc comment) doesn't restore:
// archiving what was just extracted gives the same tar.
func WriteTar(dir string, w io.Writer) error {
	files, err := TarFiles(dir)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	for _, file := range files {
		if err := writeTarEntry(tw, dir, file.Path); err != nil {
			return err
		}
	}
	return tw.Close()
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
// which ExtractTar would refuse.
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

// normalizeHeader clears every field of hdr that reflects incidental
// local filesystem state rather than a file's actual content — its
// modification/access/change times and owning uid/gid/user/group —
// so two tars of the same file content and names come out
// byte-identical regardless of when or where those files happened to
// sit on disk. Leaving the timestamps at their zero time.Time value is
// enough: archive/tar substitutes the Unix epoch for a zero ModTime on
// its own, and simply omits a zero AccessTime/ChangeTime.
func normalizeHeader(hdr *tar.Header) {
	hdr.ModTime = time.Time{}
	hdr.AccessTime = time.Time{}
	hdr.ChangeTime = time.Time{}
	hdr.Uid = 0
	hdr.Gid = 0
	hdr.Uname = ""
	hdr.Gname = ""
}

// ExtractTar extracts every entry from tr into destDir.
//
// Entry names come from the tar stream — untrusted input, whether the
// archive is bomify's own or a foreign one — so each is rejected if, once
// cleaned, it would resolve outside destDir (a "zip slip" path-traversal
// attempt via "../" segments or an absolute path) rather than being
// joined into a filesystem write.
//
// Every write goes through an os.Root of destDir, so not even a symlink
// the tar made earlier can lead one outside it, and every symlink is
// checked once all are in place (see fsutil.CheckSymlinks).
func ExtractTar(tr *tar.Reader, destDir string) error {
	if err := extractTar(tr, destDir); err != nil {
		return err
	}
	return fsutil.CheckSymlinks(destDir)
}

// extractTar is ExtractTar, short of checking the symlinks.
func extractTar(tr *tar.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, DirPerm); err != nil {
		return err
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return err
	}
	defer root.Close()

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		// hdr.Name is always "/"-separated per the tar format spec,
		// regardless of host OS, so check its rawest form for a leading
		// "/" here: filepath.IsAbs on the FromSlash-converted name isn't
		// portable for this — on Windows it only considers a
		// drive-lettered path absolute, so a POSIX-style "/etc/..." entry
		// would silently pass that check while still not being a path
		// this destDir-relative extraction should ever honor.
		if strings.HasPrefix(hdr.Name, "/") {
			return fmt.Errorf("unsafe tar entry name %q: absolute path", hdr.Name)
		}

		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe tar entry name %q: escapes destination", hdr.Name)
		}

		// A sparse file's holes read back as zeros, so a few bytes of tar
		// could declare, and fill the disk with, terabytes of them.
		// WriteTar never writes one.
		if isSparse(hdr) {
			return fmt.Errorf("unsupported tar entry %q: sparse file", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, DirPerm); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(name), DirPerm); err != nil {
				return err
			}
			mode := fs.FileMode(hdr.Mode) & fs.ModePerm
			f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := root.MkdirAll(filepath.Dir(name), DirPerm); err != nil {
				return err
			}
			// Where it points is checked once every file it might point
			// to is in place (see fsutil.CheckSymlinks).
			if err := root.Symlink(filepath.FromSlash(hdr.Linkname), name); err != nil {
				return err
			}
		default:
			// WriteTar only ever writes regular files and
			// symlinks; silently skip anything else (devices, ...) a
			// foreign tar might contain rather than trying to recreate it.
		}
	}
}

// isSparse reports whether hdr is a sparse file: in the old GNU format,
// or in PAX's, which archive/tar reports as a regular file with
// "GNU.sparse." records.
func isSparse(hdr *tar.Header) bool {
	if hdr.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for key := range hdr.PAXRecords {
		if strings.HasPrefix(key, "GNU.sparse.") {
			return true
		}
	}
	return false
}
