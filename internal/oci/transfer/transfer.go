// Package transfer holds the pieces internal/oci/pull, internal/oci/push,
// and internal/oci/save need to agree on: the OCI artifact type and
// annotation bomify's package format uses, the progress-reporting contract
// Pull and Push expose to their callers, a filename-safety check for
// untrusted OCI annotations, and the tar/untar primitives all three use to
// pack a directory into a single blob and unpack one back.
package transfer

import (
	"io"
	"io/fs"
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

// DirPerm is the permission bits of every directory bomify creates while
// restoring a package into a data directory: tar entries' parents, large
// files' parents, and staging directories.
const DirPerm fs.FileMode = 0o755
