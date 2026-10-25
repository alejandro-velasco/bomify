package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/package-url/packageurl-go"
	"oras.land/oras-go/v2"
	orasregistry "oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
)

// TaggedComponent is a component, or the platforms of one, Push tagged in
// a repository of its own beside the package's.
type TaggedComponent struct {
	// Purls are the components tagged there: one, or each platform of an
	// index.
	Purls []string
	// Reference is "<repository>:<tag>", or "<repository>@<digest>" for an
	// image pinned by digest, and Digest what it names.
	Reference string
	Digest    string
}

// ErrComponentRepository is what Push's error wraps when tagging a
// component in its own repository fails, as it does on a registry that
// can't host nested repositories, or doesn't create them on push, or when
// a component can't be placed in one (see planSites).
var ErrComponentRepository = errors.New("component repository")

// siteMember is one component manifest a site names: the manifest the
// package's index has for the component, at the site its purl gives it.
type siteMember struct {
	site     componentSite
	manifest ocispec.Descriptor
}

// componentSitePlan is what's tagged at one site: one component's
// manifest, or each platform's of one, as an index.
type componentSitePlan struct {
	site    componentSite
	members []siteMember
	// purls are the components tagged at site: each member's, and each
	// whose manifest a member already is.
	purls []string
}

// planSites plans where each of components, pushed as manifests, is
// tagged beside the package (see componentSiteOf), those sharing a site
// together, in order. Components sharing a site must be the same
// manifest, tagged once, or platforms of one component: the same purl but
// for distinct "os" and "arch" qualifiers. A component that can't be
// placed, one whose purl names no site or that would collide with
// another's, is left out of every site, and the error, joining why for
// each, is ErrComponentRepository: it fails a push that tags, before
// the index is pushed or anything tagged, but not one that doesn't, whose
// index just names no site for it. For example, these components of a
// package pushed to registry.example.com/packages/app:
//
//	pkg:oci/app@1.0?os=linux&arch=amd64
//	pkg:generic/tool@1.0?download_url=https://a.example.com/tool
//	pkg:oci/app@1.0?os=linux&arch=arm64
//	pkg:generic/tool@1.0?download_url=https://b.example.com/tool
//	pkg:helm/podinfo@6.7.1
//
// give these sites, the second tool tagged with the first if it's the
// same manifest, and left out as a collision if it isn't:
//
//	registry.example.com/packages/app/oci/app:1.0         app's amd64 and arm64 manifests, as an index
//	registry.example.com/packages/app/generic/tool:1.0    the tool
//	registry.example.com/packages/app/helm/podinfo:6.7.1  the chart
func planSites(components []cdx.Component, manifests []componentManifest) ([]*componentSitePlan, error) {
	var sites []*componentSitePlan
	var unplaced []error
	sitesByReference := map[string]*componentSitePlan{}
	for index, component := range components {
		purl, err := packageurl.FromString(component.PackageURL)
		if err != nil {
			unplaced = append(unplaced, fmt.Errorf("parse purl %q: %w", component.PackageURL, err))
			continue
		}
		site, err := componentSiteOf(purl)
		if err != nil {
			unplaced = append(unplaced, err)
			continue
		}

		// Sites are organized by reference: components at one share its
		// plan, the first creating it, in the order sites first appear.
		plan, planned := sitesByReference[site.reference()]
		if !planned {
			plan = &componentSitePlan{site: site}
			sitesByReference[site.reference()] = plan
			sites = append(sites, plan)
		}
		member := siteMember{
			site:     site,
			manifest: manifests[index].desc,
		}
		if err := plan.addMember(member, component.PackageURL); err != nil {
			unplaced = append(unplaced, err)
		}
	}
	if len(unplaced) > 0 {
		joined := errors.Join(unplaced...)
		return sites, fmt.Errorf("%w: %w", ErrComponentRepository, joined)
	}
	return sites, nil
}

// addMember adds member, purl's, to s, unless it's the same manifest as a
// member already there, which is tagged once. Either way, purl is one of
// s's.
func (s *componentSitePlan) addMember(member siteMember, purl string) error {
	for index, existing := range s.members {
		if existing.manifest.Digest == member.manifest.Digest {
			s.purls = append(s.purls, purl)
			return nil
		}
		if !member.site.isOtherPlatformOf(existing.site) {
			return fmt.Errorf("%s and %s would both be tagged %s, with different content", s.purls[index], purl, s.site.reference())
		}
	}
	s.members = append(s.members, member)
	s.purls = append(s.purls, purl)
	return nil
}

// componentTagger tags components' manifests, which Push pushed to source,
// the package's repository, ref, in repositories beside it.
type componentTagger struct {
	source oras.ReadOnlyTarget
	ref    string
	opts   transfer.Options
}

// tagAll tags each of sites (see tag), in order.
func (t componentTagger) tagAll(ctx context.Context, sites []*componentSitePlan) ([]TaggedComponent, error) {
	tagged := make([]TaggedComponent, 0, len(sites))
	for _, site := range sites {
		result, err := t.tag(ctx, site)
		if err != nil {
			return nil, fmt.Errorf("tag %s at %w %s: %w", site.purls[0], ErrComponentRepository, site.site.reference(), err)
		}
		tagged = append(tagged, result)
	}
	return tagged, nil
}

// tag copies site's members into its repository (see copyManifest), and
// for several platforms an index of them, signs what the site names if
// t's options sign, and tags it, unless it's an image pinned by digest.
func (t componentTagger) tag(ctx context.Context, site *componentSitePlan) (TaggedComponent, error) {
	packageRepository := prefix.Repository(t.ref)
	repository := path.Join(packageRepository, site.site.path)
	target, err := t.opts.ComponentTarget(repository)
	if err != nil {
		return TaggedComponent{}, err
	}

	manifests := make([]ocispec.Descriptor, 0, len(site.members))
	for _, member := range site.members {
		if err := t.copyManifest(ctx, target, member.manifest, site.purls[0]); err != nil {
			return TaggedComponent{}, err
		}
		manifest := member.manifest
		if len(site.members) > 1 {
			platform := ocispec.Platform{
				OS:           member.site.os,
				Architecture: member.site.arch,
			}
			manifest.Platform = &platform
		}
		manifests = append(manifests, manifest)
	}
	named := manifests[0]
	if len(manifests) > 1 {
		if named, err = pushPlatformIndex(ctx, target, manifests); err != nil {
			return TaggedComponent{}, err
		}
	}

	reference := repository + ":" + site.site.tag
	if site.site.tag == "" {
		reference = prefix.Pinned(repository, named.Digest.String())
	}
	if t.opts.Sign != nil {
		if err := t.opts.Sign(ctx, target, reference, named); err != nil {
			return TaggedComponent{}, fmt.Errorf("sign: %w", err)
		}
	}
	if site.site.tag != "" {
		if err := target.Tag(ctx, named, site.site.tag); err != nil {
			return TaggedComponent{}, fmt.Errorf("tag: %w", err)
		}
	}

	result := TaggedComponent{
		Purls:     site.purls,
		Reference: reference,
		Digest:    named.Digest.String(),
	}
	return result, nil
}

// copyManifest copies manifest, purl's, and what it refers to, from t's source to
// target with oras.CopyGraph, which pushes what a manifest names before
// the manifest, and skips what target already has. Each blob is mounted
// from the package's repository (see transfer.MountBlob), so a registry
// that stores a blob once is sent it once; a manifest, which a registry
// can't mount, is pushed.
func (t componentTagger) copyManifest(ctx context.Context, target oras.Target, manifest ocispec.Descriptor, purl string) error {
	from := t.mountFrom()
	mountBlob := func(ctx context.Context, desc ocispec.Descriptor) error {
		if slices.Contains(transfer.ManifestMediaTypes, desc.MediaType) {
			return nil
		}
		open := func() (io.ReadCloser, error) {
			return t.source.Fetch(ctx, desc)
		}
		label := transfer.LayerLabel(purl, desc.Digest.Encoded())
		if err := transfer.MountBlob(ctx, target, desc, from, open, label, t.opts.Progress); err != nil {
			return err
		}
		// Now in target, so CopyGraph doesn't copy it again.
		return oras.SkipNode
	}
	copyOpts := oras.CopyGraphOptions{
		Concurrency: t.opts.Concurrency,
		PreCopy:     mountBlob,
	}
	if err := oras.CopyGraph(ctx, t.source, target, manifest, copyOpts); err != nil {
		return fmt.Errorf("copy %s: %w", manifest.Digest, err)
	}
	return nil
}

// mountFrom returns the package's repository, without its registry, which
// blobs are mounted from (see transfer.MountBlob), or "" if t's ref
// doesn't parse.
func (t componentTagger) mountFrom() string {
	reference, err := orasregistry.ParseReference(prefix.Repository(t.ref))
	if err != nil {
		return ""
	}
	return reference.Repository
}

// pushPlatformIndex pushes to target an index of manifests, each a
// platform's, returning its descriptor. Like every manifest Push builds,
// it isn't annotated with the time, so it's the same on every push.
func pushPlatformIndex(ctx context.Context, target oras.Target, manifests []ocispec.Descriptor) (ocispec.Descriptor, error) {
	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: manifests[0].ArtifactType,
		Manifests:    manifests,
	}
	data, err := json.Marshal(index)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc, err := transfer.PushBytes(ctx, target, data, ocispec.MediaTypeImageIndex, "index", nil)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push index: %w", err)
	}
	desc.ArtifactType = index.ArtifactType
	return desc, nil
}
