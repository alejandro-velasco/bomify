package transfer

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
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
// so the resulting tar — and so the digest Push computes over it —
// depends only on the archived files' names, modes, and content, never
// on incidental local filesystem metadata. This matters because
// ExtractTar (deliberately, see its own doc comment) doesn't restore a
// file's original mtime/uid/gid on unpack: without normalizing here,
// re-tarring a layer bomify itself just pulled would reproduce a
// different tar — and so a different digest — than the one originally
// pushed, even though the content is byte-for-byte identical, making
// Push treat it as new and re-upload it every time.
func WriteTar(dir string, w io.Writer) error {
	files, err := TarFiles(dir)
	if err != nil {
		return err
	}
	return WriteTarFiles(dir, files, w)
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
// header block and its content padded to whole blocks, not counting the
// longer headers a long name needs.
func TarSize(size int64) int64 {
	blocks := (size + tarBlockSize - 1) / tarBlockSize
	return tarBlockSize + blocks*tarBlockSize
}

// WriteTarFiles archives files, some of TarFiles(dir), into w, as
// WriteTar does all of dir's.
func WriteTarFiles(dir string, files []TarFile, w io.Writer) error {
	return writeTar(dir, files, w, false)
}

// WriteTarTree is WriteTarFiles, but with an entry for each directory
// ahead of the first file in it, for tools that don't create a file's
// parent directories themselves, such as `oras pull`.
func WriteTarTree(dir string, files []TarFile, w io.Writer) error {
	return writeTar(dir, files, w, true)
}

// writeTar archives files, of dir, into w, each after an entry for its
// directories if dirEntries is set.
func writeTar(dir string, files []TarFile, w io.Writer, dirEntries bool) error {
	tw := tar.NewWriter(w)
	written := map[string]bool{}
	for _, file := range files {
		if dirEntries {
			if err := writeTarDirs(tw, path.Dir(file.Path), written); err != nil {
				return err
			}
		}
		if err := writeTarEntry(tw, dir, file.Path); err != nil {
			return err
		}
	}
	return tw.Close()
}

// writeTarDirs writes an entry for dir, a "/"-separated path, and each
// of its parents, that written doesn't hold yet, outermost first.
func writeTarDirs(tw *tar.Writer, dir string, written map[string]bool) error {
	if dir == "." || written[dir] {
		return nil
	}
	if err := writeTarDirs(tw, path.Dir(dir), written); err != nil {
		return err
	}
	written[dir] = true
	hdr := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     dir + "/",
		Mode:     int64(DirPerm),
	}
	normalizeHeader(hdr)
	return tw.WriteHeader(hdr)
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
	if err := extractTar(tr, destDir, os.O_TRUNC); err != nil {
		return err
	}
	return fsutil.CheckSymlinks(destDir)
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

// extractTar is ExtractTar, opening each file with flag added: O_TRUNC to
// replace one that exists, O_EXCL to fail on it.
func extractTar(tr *tar.Reader, destDir string, flag int) error {
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
			f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|flag, mode)
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
			// Bomify's own tar layers only ever contain regular files and
			// symlinks; silently skip anything else (devices, ...) a
			// foreign tar might contain rather than trying to recreate it.
		}
	}
}
