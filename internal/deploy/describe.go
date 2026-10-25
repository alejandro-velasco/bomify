package deploy

import (
	"context"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// TagResolver resolves a tagged reference to the digest it points at in
// its registry, failing with an error wrapping errdef.ErrNotFound if
// there's no such tag.
type TagResolver func(ctx context.Context, reference string) (digest.Digest, error)

// Describe is the package description (see
// plugins/contracts/deployment/v1/CONTRACT.md) of the package ref names,
// verified at packageDigest, whose components are components. Each
// component is pinned in ref's repository by digest, and Tagged where its
// index entry says push tagged it, only if resolve finds that tag pointing
// at it.
func Describe(ctx context.Context, ref, packageDigest string, components []pull.PackageComponent, resolve TagResolver) (pluginlib.DeploymentPackage, error) {
	repository := prefix.Repository(ref)
	description := pluginlib.DeploymentPackage{
		Reference:  ref,
		Repository: repository,
		Digest:     packageDigest,
		Components: make([]pluginlib.DeploymentComponent, 0, len(components)),
	}
	for _, listed := range components {
		manifest := listed.Manifest
		if manifest.Digest == "" {
			return pluginlib.DeploymentPackage{}, fmt.Errorf("component %s isn't in the package's index", listed.Component.PackageURL)
		}
		tagged, err := tag(ctx, listed.Reference, manifest.Digest, resolve)
		if err != nil {
			return pluginlib.DeploymentPackage{}, fmt.Errorf("component %s: %w", listed.Component.PackageURL, err)
		}
		component := pluginlib.DeploymentComponent{
			Name:         listed.Component.Name,
			Version:      listed.Component.Version,
			Purl:         listed.Component.PackageURL,
			ArtifactType: manifest.ArtifactType,
			Digest:       manifest.Digest.String(),
			Reference:    prefix.Pinned(repository, manifest.Digest.String()),
			Tagged:       tagged,
		}
		description.Components = append(description.Components, component)
	}
	return description, nil
}

// tag is where reference, a component's tag as its index entry gives
// it, tags the component whose manifest is manifest, or nil if reference
// is empty or pinned by digest, or its tag is missing or points
// elsewhere: a package copied without bomify, or pushed with
// --skip-component-repositories, has no tags.
func tag(ctx context.Context, reference string, manifest digest.Digest, resolve TagResolver) (*pluginlib.TaggedReference, error) {
	if reference == "" {
		return nil, nil
	}
	parsed, err := registry.ParseReference(reference)
	if err != nil {
		return nil, fmt.Errorf("parse its reference %q: %w", reference, err)
	}
	if parsed.ValidateReferenceAsDigest() == nil {
		return nil, nil
	}
	resolved, err := resolve(ctx, reference)
	if errors.Is(err, errdef.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("check its tag %s: %w", reference, err)
	}
	if resolved != manifest {
		return nil, nil
	}
	tagged := pluginlib.TaggedReference{
		Registry:   parsed.Registry,
		Repository: parsed.Repository,
		Tag:        parsed.Reference,
		Reference:  reference,
	}
	return &tagged, nil
}
