// Package sign adds signatures to a bomify package that's already
// published, in a registry or a `bomify save` tarball, without fetching
// its components: signing only needs the package index's descriptor (see
// internal/signature). So a package can be co-signed at different times,
// in different environments, each with only its own key.
package sign

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/oci/save"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// signableTypes are the artifact types of the referrers Sign can sign
// along with a package, since pulls verify them separately.
var signableTypes = []string{transfer.VulnerabilityReportsArtifactType, transfer.VEXArtifactType}

// Result is what Sign signed for one reference.
type Result struct {
	// Manifest is the package's index, newly signed.
	Manifest ocispec.Descriptor
	// Referrers are the package's vulnerability report and VEX referrers
	// that were asked for, each newly signed too.
	Referrers []ocispec.Descriptor
	// Skipped are its other vulnerability report and VEX referrers, left
	// unsigned.
	Skipped []ocispec.Descriptor
}

// Sign signs the bomify package ref names in target with signer, as push
// signs one it publishes (see transfer.Signer): the package's index,
// then each of its vulnerability report and VEX referrers whose digest
// referrers names. Anyone who can push can attach a referrer, and signing
// one vouches for it (a signed VEX document can exempt a finding), so
// none is signed unless asked for by digest. Nothing but manifests is
// fetched. It fails, signing nothing, if ref isn't a bomify package or
// one of referrers isn't among its referrers.
func Sign(ctx context.Context, target oras.Target, ref string, signer transfer.Signer, referrers []string) (Result, error) {
	pkg, err := resolve(ctx, target, ref)
	if err != nil {
		return Result{}, err
	}
	if missing := pkg.missing(referrers); len(missing) > 0 {
		return Result{}, fmt.Errorf("%s has no vulnerability report or VEX referrer %s", ref, strings.Join(missing, ", "))
	}
	return pkg.sign(ctx, target, ref, signer, referrers)
}

// resolved is a package Sign is signing: its index, and its vulnerability
// report and VEX referrers.
type resolved struct {
	manifest  ocispec.Descriptor
	referrers []ocispec.Descriptor
}

// resolve resolves ref in target, requiring a bomify package, and lists
// the referrers of it Sign can sign.
func resolve(ctx context.Context, target oras.Target, ref string) (resolved, error) {
	manifest, err := target.Resolve(ctx, ref)
	if err != nil {
		return resolved{}, fmt.Errorf("resolve %s: %w", ref, err)
	}
	if err := requirePackage(ctx, target, ref, manifest); err != nil {
		return resolved{}, err
	}
	pkg := resolved{manifest: manifest}
	for _, artifactType := range signableTypes {
		referrers, err := transfer.Referrers(ctx, target, manifest, artifactType)
		if err != nil {
			return resolved{}, err
		}
		pkg.referrers = append(pkg.referrers, referrers...)
	}
	return pkg, nil
}

// has reports whether d is the digest of one of p's referrers.
func (p resolved) has(d string) bool {
	return slices.ContainsFunc(p.referrers, func(referrer ocispec.Descriptor) bool { return referrer.Digest.String() == d })
}

// missing returns those of digests that aren't among p's referrers.
func (p resolved) missing(digests []string) []string {
	var missing []string
	for _, d := range digests {
		if !p.has(d) {
			missing = append(missing, d)
		}
	}
	return missing
}

// sign signs p's index, then each of its referrers digests names.
func (p resolved) sign(ctx context.Context, target oras.Target, ref string, signer transfer.Signer, digests []string) (Result, error) {
	if err := signer(ctx, target, ref, p.manifest); err != nil {
		return Result{}, fmt.Errorf("sign %s: %w", ref, err)
	}
	result := Result{Manifest: p.manifest}
	for _, referrer := range p.referrers {
		if !slices.Contains(digests, referrer.Digest.String()) {
			result.Skipped = append(result.Skipped, referrer)
			continue
		}
		if err := signer(ctx, target, ref, referrer); err != nil {
			return Result{}, fmt.Errorf("sign %s of %s: %w", referrer.Digest, ref, err)
		}
		result.Referrers = append(result.Referrers, referrer)
	}
	return result, nil
}

// requirePackage fails unless index, what ref resolved to, is a bomify
// package's index (see transfer.FetchPackage).
func requirePackage(ctx context.Context, target content.ReadOnlyStorage, ref string, index ocispec.Descriptor) error {
	if _, err := transfer.FetchPackage(ctx, target, index); err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	return nil
}

// TaggedResult is what SignArchive signed for one of a tarball's tags.
type TaggedResult struct {
	Tag string
	Result
}

// SignArchive signs every package tagged in r, a `bomify save` tarball,
// as Sign does, each with those of referrers that are its own, and writes
// the tarball, its existing signatures kept and the new ones added, to w.
// It fails, writing nothing, if one of referrers belongs to none of its
// packages.
func SignArchive(ctx context.Context, r io.Reader, w io.Writer, signer transfer.Signer, referrers []string) ([]TaggedResult, error) {
	archive, err := save.OpenArchive(r)
	if err != nil {
		return nil, err
	}
	defer archive.Close()

	tags, err := archive.Tags(ctx)
	if err != nil {
		return nil, err
	}

	packages := make([]resolved, len(tags))
	for i, tag := range tags {
		if packages[i], err = resolve(ctx, archive.Store, tag); err != nil {
			return nil, err
		}
	}
	for _, d := range referrers {
		if !slices.ContainsFunc(packages, func(p resolved) bool { return p.has(d) }) {
			return nil, fmt.Errorf("no package in the tarball has a vulnerability report or VEX referrer %s", d)
		}
	}

	results := make([]TaggedResult, 0, len(tags))
	for i, tag := range tags {
		result, err := packages[i].sign(ctx, archive.Store, tag, signer, referrers)
		if err != nil {
			return nil, err
		}
		tagged := TaggedResult{
			Tag:    tag,
			Result: result,
		}
		results = append(results, tagged)
	}

	if err := archive.WriteTar(w); err != nil {
		return nil, err
	}
	return results, nil
}
