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

// Scanner decides whether the package ref resolved to in target — its
// OCI manifest, manifest, whose SBOM (the package's config blob) is
// sbom — may be restored, typically by scanning the components it
// describes for vulnerabilities (see internal/security); target and
// manifest let it read what's attached to the package, such as VEX.
// Pull calls it after Verifier, before writing anything at all, so a
// failed Scanner leaves nothing behind in the data directory either.
type Scanner func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, sbom []byte) error

// Attester signs statement, an in-toto statement about the package Push
// has just packed into target (its manifest, subject), as a DSSE
// attestation, and pushes it into target as a referrer of subject carrying
// annotations. Push calls it, like Signer, before tagging ref.
type Attester func(ctx context.Context, target oras.Target, ref string, subject ocispec.Descriptor, statement []byte, annotations map[string]string) (ocispec.Descriptor, error)

// Options are what Push, Pull, and Save/Load take beyond what to
// transfer: how, and the optional steps to run around a package.
type Options struct {
	// Concurrency bounds how many layers transfer at once; values less
	// than 1 are treated as 1.
	Concurrency int
	// Progress reports each blob's transfer; nil reports nothing.
	Progress ProgressFunc

	// Sign is called when pushing; Verify, VerifyProvenance, and then Scan
	// when pulling. Any may be nil. Unlike Verify, which also checks what's
	// attached to a package, VerifyProvenance is only called with the
	// package itself.
	Sign             Signer
	Verify           Verifier
	VerifyProvenance Verifier
	Scan             Scanner
	// Attest signs the package's build provenance, if it has any; without
	// it, provenance is attached unsigned.
	Attest Attester

	// Attach are documents Push attaches to every package it pushes, each
	// as its own referrer, signed like the package (see transfer.Attach).
	Attach []Attachment
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
