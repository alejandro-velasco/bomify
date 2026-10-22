// Package transfer holds the pieces internal/oci/pull, internal/oci/push,
// and internal/oci/save need to agree on: the types and annotations
// bomify's package format uses (see Package), the progress-reporting contract
// Pull and Push expose to their callers, a filename-safety check for
// untrusted OCI annotations, and the tar/untar primitives save uses to
// archive a directory and unpack one back.
package transfer

import (
	"io"
	"io/fs"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ArtifactType identifies a bomify package: an OCI image index of the
// SBOM's manifest and each component's (see Package).
const ArtifactType = "application/vnd.bomify.package.v1+json"

// AnnotationPurl is the OCI annotation naming the purl of the component a
// package index entry, layer, or report is of.
const AnnotationPurl = "land.bomify.purl"

// VulnerabilityReportMediaType identifies a component's vulnerability
// report blob: the CycloneDX document `bomify security scan` wrote for
// it (see internal/security), annotated with its AnnotationPurl. Push attaches every report that exists
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
// component on any OS bomify runs on, for a name that comes from whoever
// published an artifact, such as a vulnerability report's scanner (see
// internal/security). It must be valid UTF-8, at most maxFilenameBytes
// long, and free of:
//   - separators and traversal ("/", "\", ".", "..");
//   - the other characters Windows reserves (":*?\"<>|") and control
//     characters, NUL among them;
//   - a trailing dot or space, which Windows drops, naming another file;
//   - a name Windows reserves for a device, such as "CON" or "nul.json".
func IsSafeFilename(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > maxFilenameBytes {
		return false
	}
	if !utf8.ValidString(name) || strings.ContainsAny(name, `/\:*?"<>|`) || strings.ContainsFunc(name, unicode.IsControl) {
		return false
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	// Windows reserves a device's name whatever follows its first dot, and
	// ignores spaces before that dot.
	device, _, _ := strings.Cut(name, ".")
	device = strings.ToUpper(strings.TrimRight(device, " "))
	return !slices.Contains(windowsDevices, device)
}

// maxFilenameBytes is the longest name IsSafeFilename accepts: short of
// the 255 bytes most file systems allow in one path component, leaving
// room for a suffix bomify appends, such as a report's ".json".
const maxFilenameBytes = 200

// windowsDevices are the names Windows reserves for devices, in upper
// case.
var windowsDevices = []string{
	"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
	"COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
	"LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
}

// DirPerm is the permission bits of every directory bomify creates while
// restoring a package into a data directory, files' parents and staging
// directories, or unpacking a tar.
const DirPerm fs.FileMode = 0o755
