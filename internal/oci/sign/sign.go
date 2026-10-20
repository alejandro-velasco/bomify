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

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/oci/save"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// Result is what Sign signed for one reference.
type Result struct {
	// Manifest is the package's index, newly signed.
	Manifest ocispec.Descriptor
	// Referrers are the package's vulnerability report and VEX referrers,
	// each newly signed too.
	Referrers []ocispec.Descriptor
}

// Sign signs the bomify package ref names in target with signer, as push
// signs one it publishes (see transfer.Signer): the package's index,
// then each of its vulnerability report and VEX referrers, so they keep
// verifying under trust rules requiring every signer. Nothing but
// manifests is fetched. It fails if ref isn't a bomify package.
func Sign(ctx context.Context, target oras.Target, ref string, signer transfer.Signer) (Result, error) {
	manifest, err := target.Resolve(ctx, ref)
	if err != nil {
		return Result{}, fmt.Errorf("resolve %s: %w", ref, err)
	}
	if err := requirePackage(ctx, target, ref, manifest); err != nil {
		return Result{}, err
	}

	if err := signer(ctx, target, ref, manifest); err != nil {
		return Result{}, fmt.Errorf("sign %s: %w", ref, err)
	}
	result := Result{Manifest: manifest}

	for _, artifactType := range []string{transfer.VulnerabilityReportsArtifactType, transfer.VEXArtifactType} {
		referrers, err := transfer.Referrers(ctx, target, manifest, artifactType)
		if err != nil {
			return Result{}, err
		}
		for _, referrer := range referrers {
			if err := signer(ctx, target, ref, referrer); err != nil {
				return Result{}, fmt.Errorf("sign %s of %s: %w", referrer.Digest, ref, err)
			}
			result.Referrers = append(result.Referrers, referrer)
		}
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
// as Sign does, and writes the tarball, its existing signatures kept and
// the new ones added, to w.
func SignArchive(ctx context.Context, r io.Reader, w io.Writer, signer transfer.Signer) ([]TaggedResult, error) {
	archive, err := save.OpenArchive(r)
	if err != nil {
		return nil, err
	}
	defer archive.Close()

	tags, err := archive.Tags(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]TaggedResult, 0, len(tags))
	for _, tag := range tags {
		result, err := Sign(ctx, archive.Store, tag, signer)
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
