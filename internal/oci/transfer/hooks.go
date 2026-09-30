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

// Hooks are the optional steps Push and Pull run around a package: Sign
// when pushing, Verify and then Scan when pulling. Any may be nil.
type Hooks struct {
	Sign   Signer
	Verify Verifier
	Scan   Scanner
}
