package transfer

import (
	"context"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
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
// OCI manifest, manifest, whose SBOM (the package's config blob, parsed)
// is bom — may be restored, typically by scanning the components it
// describes for vulnerabilities (see internal/security); target and
// manifest let it read what's attached to the package, such as VEX.
// Pull calls it once the package's component layers are written, so it
// can scan their files, and fails if it does: the package is left in the
// data directory but untagged, for "bomify package prune" to reclaim.
type Scanner func(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, bom *cdx.BOM) error

// Attester signs statement, an in-toto statement about the package Push
// has just packed into target (its manifest, subject), as a DSSE
// attestation, and pushes it into target as a referrer of subject carrying
// annotations. Push calls it, like Signer, before tagging ref.
type Attester func(ctx context.Context, target oras.Target, ref string, subject ocispec.Descriptor, statement []byte, annotations map[string]string) (ocispec.Descriptor, error)

// ComponentPacker packs the components Push publishes at their own
// repositories, each in its kind's own registry format, typically with its
// plugin's "pack" (see plugins/contracts/component/v1/CONTRACT.md).
type ComponentPacker interface {
	// CanPack fails if component can't be packed, as when its plugin
	// isn't installed. Push calls it for every component before pushing
	// anything.
	CanPack(component cdx.Component) error
	// Pack packs component, which a prior pull wrote into input, writing
	// any blob it builds into output and adding annotations to the
	// manifest it builds. The zero PackResult means the component's kind
	// has no format of its own.
	Pack(ctx context.Context, component cdx.Component, input, output string, annotations map[string]string) (pluginlib.PackResult, error)
}

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
	// ComponentTarget, if set, returns the target for another repository
	// of the registry Push pushes to, where Push publishes each of the
	// package's components, signed like the package. Nil publishes only
	// the package.
	ComponentTarget func(repository string) (oras.Target, error)
	// ComponentPacker packs each component ComponentTarget's repositories
	// get. Nil publishes every component as an artifact of its files.
	ComponentPacker ComponentPacker
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
