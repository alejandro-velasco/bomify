// Package transfer holds the pieces internal/oci/pull, internal/oci/push,
// and internal/oci/save need to agree on: the OCI artifact type and
// annotation bomify's package format uses, the progress-reporting contract
// Pull and Push expose to their callers, a filename-safety check for
// untrusted OCI annotations, and the tar/untar primitives all three use to
// pack a directory into a single blob and unpack one back.
package transfer

import (
	"archive/tar"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ArtifactType identifies a bomify package: an OCI artifact whose config is
// the aggregate SBOM manifest (see internal/build) and whose layers are the
// components that SBOM describes.
const ArtifactType = "application/vnd.bomify.package.v1+json"

// AnnotationPurl is the OCI descriptor annotation identifying the purl a
// layer was pulled from, or is being pushed for.
const AnnotationPurl = "land.bomify.purl"

// LayerMediaType identifies a pushed component layer: a tar archive of
// whatever `bomify build` wrote into "<baseDir>/layers/<purl-hash>/" for
// it, since that can be a single file (bomify-plugin-generic) or a whole
// directory tree (bomify-plugin-oci's OCI layout) and an OCI layer is
// always exactly one blob. Pull unpacks a layer with this media type back
// into "<dataDir>/layers/<purl-hash>/", exactly reproducing the directory
// build would have produced; any other media type (e.g. a real-world
// artifact this package format didn't originate) is instead written
// verbatim as a single file, since Pull has no way to know how to unpack
// an arbitrary foreign format.
const LayerMediaType = "application/vnd.bomify.component.layer.v1.tar"

// ProgressFunc is called once per blob (the config, then each layer) before
// it starts transferring, naming it and giving its total size in bytes. The
// returned writer receives the raw bytes as they're transferred, for
// rendering a progress bar, and is closed once that blob's transfer ends
// (successfully or not). A nil ProgressFunc is fine; Pull/Push render no
// progress in that case.
type ProgressFunc func(name string, size int64) io.WriteCloser

// Discard is a no-op ProgressFunc, for callers that don't want progress
// reporting.
func Discard(string, int64) io.WriteCloser { return discardWriteCloser{} }

type discardWriteCloser struct{}

func (discardWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriteCloser) Close() error                { return nil }

// IsSafeFilename reports whether name is usable, as-is, as a single path
// component on any OS bomify runs on: no separators, no traversal, and none
// of the characters Windows reserves (":*?\"<>|" plus the two we already
// check for on every platform, "/" and "\"). Both Pull (reading an OCI
// title annotation from whoever published the artifact) and Push (choosing
// a title to publish) treat that annotation as untrusted input.
func IsSafeFilename(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, `/\:*?"<>|`)
}

// WriteTar archives every regular file under dir into w as a tar stream,
// with paths relative to dir. It never writes explicit directory entries:
// a tar reader reconstructs a file's parent directories from its path
// alone, so those would be redundant.
func WriteTar(dir string, w io.Writer) error {
	tw := tar.NewWriter(w)

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}

	return tw.Close()
}

// ExtractTar extracts every entry from tr into destDir.
//
// Entry names come from the tar stream — untrusted input, whether the
// archive is bomify's own or a foreign one — so each is rejected if, once
// cleaned, it would resolve outside destDir (a "zip slip" path-traversal
// attempt via "../" segments or an absolute path) rather than being
// joined into a filesystem write.
func ExtractTar(tr *tar.Reader, destDir string) error {
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
		target := filepath.Join(destDir, name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode) & 0o777
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
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
		default:
			// Bomify's own tar layers only ever contain regular files;
			// silently skip anything else (symlinks, devices, ...) a
			// foreign tar might contain rather than trying to recreate it.
		}
	}
}
