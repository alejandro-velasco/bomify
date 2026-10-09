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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
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
// it — a single file or a whole directory tree, since an OCI layer is
// always exactly one blob either way. Pull unpacks a layer with this
// media type back into that same directory shape; any other media type
// is instead written verbatim as a single file, since Pull has no way to
// know how to unpack an arbitrary foreign format.
const LayerMediaType = "application/vnd.bomify.component.layer.v1.tar"

// VulnerabilityReportMediaType identifies a component's vulnerability
// report blob: the CycloneDX document `bomify security scan` wrote for
// it (see internal/security), annotated with the same AnnotationPurl as
// the component's own layer. Push attaches every report that exists
// locally at push time as a layer of one VulnerabilityReportsArtifactType
// referrer of the package — a component never scanned, or one no
// installed scanner supports, simply carries none. Pull writes each
// straight to "<baseDir>/vulnerabilities/<purl-hash>.json" — the same
// path a scan itself would have written it to — rather than unpacking or
// verbatim-copying it like a component layer.
const VulnerabilityReportMediaType = "application/vnd.bomify.component.vulnerabilities.v1+json"

// VulnerabilityReportsArtifactType identifies an OCI referrer of a
// bomify package carrying the vulnerability reports of one scan (see
// internal/security). Keeping reports out of the package manifest keeps
// its digest — and so every signature over it — unchanged by a re-scan.
const VulnerabilityReportsArtifactType = "application/vnd.bomify.vulnerabilities.v1+json"

// AnnotationAttestation marks a referrer as an attestation about a
// package, rather than the package's own signature, naming its in-toto
// predicate type. Signature verification skips these.
const AnnotationAttestation = "land.bomify.attestation.predicateType"

// VEXArtifactType identifies an OCI referrer of a bomify package carrying
// one VEX document its publisher attached (see Attach and
// internal/security).
const VEXArtifactType = "application/vnd.bomify.vex.v1+json"

// VEXDocumentMediaType identifies a VEX referrer's one layer: the
// document itself, in whichever format it was written (OpenVEX, CSAF, or
// CycloneDX VEX, told apart by content).
const VEXDocumentMediaType = "application/vnd.bomify.vex.document.v1"

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

// extractTar is ExtractTar, opening each file with flag added: O_TRUNC to
// replace one that exists, O_EXCL to fail on it.
func extractTar(tr *tar.Reader, destDir string, flag int) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
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
			if err := root.MkdirAll(name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode) & 0o777
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
			if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
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
