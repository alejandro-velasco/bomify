package transfer

import (
	"context"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
)

// Signer signs a bomify package Push has just packed into target — its
// OCI manifest, manifest, about to be tagged ref — typically by pushing a
// signature referrer of manifest into that same target (see
// internal/signature). Push calls it before tagging, so a failed Signer
// leaves ref untouched rather than pointing at an unsigned package.
type Signer func(ctx context.Context, target oras.Target, ref string, manifest ocispec.Descriptor) error

// Verifier decides whether the package ref resolved to in target — its
// OCI manifest, manifest — may be restored at all. Pull calls it before
// fetching anything else, so a failed Verifier leaves nothing behind in
// the data directory.
type Verifier func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor) error

// Scanner decides whether the package ref resolved to — whose SBOM, the
// package's config blob, is sbom — may be restored, typically by
// scanning the components it describes for vulnerabilities (see
// internal/security). Pull calls it after Verifier, before writing
// anything at all, so a failed Scanner leaves nothing behind in the data
// directory either.
type Scanner func(ctx context.Context, ref string, sbom []byte) error

// Options are what Push, Pull, and Save/Load take beyond what to
// transfer: how, and the optional steps to run around a package.
type Options struct {
	// Concurrency bounds how many layers transfer at once; values less
	// than 1 are treated as 1.
	Concurrency int
	// Progress reports each blob's transfer; nil reports nothing.
	Progress ProgressFunc

	// Sign is called when pushing; Verify and then Scan when pulling. Any
	// may be nil.
	Sign   Signer
	Verify Verifier
	Scan   Scanner
}

// WithDefaults returns o with Concurrency at least 1 and a non-nil
// Progress, so callers can use both unconditionally.
func (o Options) WithDefaults() Options {
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	if o.Progress == nil {
		o.Progress = Discard
	}
	return o
}
