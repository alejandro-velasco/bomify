// Package ocitransfer holds the pieces internal/ocipull and internal/ocipush
// need to agree on: the OCI artifact type and annotation bomify's package
// format uses, the progress-reporting contract both Pull and Push expose to
// their callers, and a filename-safety check for untrusted OCI annotations.
package ocitransfer

import (
	"io"
	"strings"
)

// ArtifactType identifies a bomify package: an OCI artifact whose config is
// the aggregate SBOM manifest (see internal/build) and whose layers are the
// components that SBOM describes.
const ArtifactType = "application/vnd.bomify.package.v1+json"

// AnnotationPurl is the OCI descriptor annotation identifying the purl a
// layer was pulled from, or is being pushed for.
const AnnotationPurl = "land.bomify.purl"

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
