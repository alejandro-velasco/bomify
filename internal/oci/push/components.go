package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// What Push publishes for a component at its own repository, unless it's
// a model: an artifact of ComponentArtifactType, its small files in one
// layer of ComponentTarGzMediaType, its large files in layers of
// transfer.FileMediaType, and the artifact annotated with
// AnnotationPackageDigest, the package it was published with.
const (
	ComponentArtifactType   = "application/vnd.bomify.component.v1+json"
	ComponentTarGzMediaType = "application/vnd.bomify.component.layer.v1.tar+gzip"
	AnnotationPackageDigest = "land.bomify.package.digest"
)

// componentRepositoryLabel ends a blob's label in progress output when
// it's pushed to a component's repository.
const componentRepositoryLabel = " (component repository)"

// PublishedComponent is a component, or the platforms of one, that Push
// published at its own repository.
type PublishedComponent struct {
	// Purls are the components published there: one, or each platform of
	// an index.
	Purls []string
	// Reference is "<repository>:<tag>", and Digest what it points at.
	Reference string
	Digest    string
}

// ErrComponentRepository is what Push's error wraps when publishing a
// component at its own repository fails, as it does on a registry that
// can't host nested repositories, or doesn't create them on push.
var ErrComponentRepository = errors.New("component repository")

// componentLayers are a component of a pushed package, and the layers
// Push pushed for it: plans, pushed as descs.
type componentLayers struct {
	component cdx.Component
	plans     []layerPlan
	descs     []ocispec.Descriptor
}

// dir is the directory c's files are in.
func (c componentLayers) dir() string {
	return c.plans[0].directory()
}

// sameContent reports whether c and other were pushed as the same
// layers.
func (c componentLayers) sameContent(other componentLayers) bool {
	return slices.EqualFunc(c.descs, other.descs, func(a, b ocispec.Descriptor) bool { return a.Digest == b.Digest })
}

// splitByComponent groups plans, pushed as descs, by component, in
// components' order.
func splitByComponent(components []cdx.Component, plans []layerPlan, descs []ocispec.Descriptor) []componentLayers {
	byPurl := make(map[string]*componentLayers, len(components))
	grouped := make([]componentLayers, 0, len(components))
	for _, component := range components {
		if _, seen := byPurl[component.PackageURL]; seen {
			continue
		}
		grouped = append(grouped, componentLayers{component: component})
		byPurl[component.PackageURL] = &grouped[len(grouped)-1]
	}
	for index, plan := range plans {
		entry := byPurl[plan.owner().PackageURL]
		entry.plans = append(entry.plans, plan)
		entry.descs = append(entry.descs, descs[index])
	}
	return grouped
}

// publishOptions are what every publisher of a push shares: the package
// its components are published from, pushed as ref but not yet tagged,
// and how.
type publishOptions struct {
	pkg  *pushedPackage
	ref  string
	opts transfer.Options
}

// mountSource returns the repository of the registry the package was
// pushed to that already holds the blob desc names, for a component's
// repository to mount it from rather than upload it again, or "" if the
// package pushed no such blob. A large file is one of the package's
// layers, with the same digest.
func (o publishOptions) mountSource(desc ocispec.Descriptor) string {
	pushed := slices.ContainsFunc(o.pkg.layerDescs, func(layer ocispec.Descriptor) bool {
		return layer.Digest == desc.Digest
	})
	if !pushed {
		return ""
	}
	reference, err := orasregistry.ParseReference(prefix.Repository(o.ref))
	if err != nil {
		return ""
	}
	return reference.Repository
}

// pushBlob makes desc available in target: mounted from from, a repository
// of the registry that holds it (see mountSource), if target can mount,
// and otherwise pushed from the content open returns.
func (o publishOptions) pushBlob(ctx context.Context, target oras.Target, desc ocispec.Descriptor, from string, open func() (io.ReadCloser, error), label string) error {
	if mountTarget, canMount := target.(transfer.MountTarget); canMount && from != "" {
		return transfer.MountBlob(ctx, mountTarget, desc, from, open, label, o.opts.Progress)
	}
	content, err := open()
	if err != nil {
		return err
	}
	defer content.Close()
	return transfer.PushBlob(ctx, target, desc, content, label, o.opts.Progress)
}

// publisher publishes a component at its own repository, target, in one
// format (see newPublisher), returning the descriptor of what it pushed.
// publication is what it publishes.
type publisher interface {
	publication() componentPublication
	publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error)
}

// componentPublication is what a publisher publishes: a component of the
// package, as Push pushed its layers, at its site.
type componentPublication struct {
	publishOptions
	componentLayers
	site componentSite
}

func (c componentPublication) publication() componentPublication {
	return c
}

// annotations returns the annotations of what's published for c's
// component: its purl, the package's digest, and the package's created
// time, so publishing an unchanged package gives the same digests.
func (c componentPublication) annotations() map[string]string {
	annotations := map[string]string{
		ocispec.AnnotationCreated: c.pkg.created,
		transfer.AnnotationPurl:   c.component.PackageURL,
		AnnotationPackageDigest:   c.pkg.desc.Digest.String(),
	}
	return annotations
}

// newPublisher returns the publisher of publication, by its component's
// purl type: an image as it is (see imagePublisher), a chart as Helm
// stores one (see chartPublisher), and anything else as an artifact of
// its files (see artifactPublisher).
func newPublisher(publication componentPublication) publisher {
	switch publication.site.kind {
	case packageurl.TypeOCI, packageurl.TypeDocker:
		return imagePublisher{publication}
	case packageurl.TypeHelm:
		return chartPublisher{publication}
	default:
		return artifactPublisher{publication}
	}
}

// siteGroup is the publishers of the components published at one site:
// one, or each platform of an index.
type siteGroup struct {
	site    componentSite
	members []publisher
}

// add adds member to g, unless it publishes the same content as a member
// already there.
func (g *siteGroup) add(member publisher) error {
	added := member.publication()
	for _, existing := range g.members {
		other := existing.publication()
		if other.sameContent(added.componentLayers) {
			return nil
		}
		platforms := other.site.hasPlatform() && added.site.hasPlatform() && (other.site.os != added.site.os || other.site.arch != added.site.arch)
		if other.site.unqualified != added.site.unqualified || !platforms {
			return fmt.Errorf("%s and %s would both be published at %s, with different content", other.component.PackageURL, added.component.PackageURL, added.site.reference())
		}
	}
	g.members = append(g.members, member)
	return nil
}

// publish runs g's publishers against target, returning the descriptor
// of what g's site names: its one member's, or an index of every
// member's, each for its platform.
func (g *siteGroup) publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	descs := make([]ocispec.Descriptor, 0, len(g.members))
	for _, member := range g.members {
		desc, err := member.publish(ctx, target)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		if len(g.members) > 1 {
			site := member.publication().site
			desc.Platform = &ocispec.Platform{OS: site.os, Architecture: site.arch}
		}
		descs = append(descs, desc)
	}
	if len(descs) == 1 {
		return descs[0], nil
	}
	return g.pushIndex(ctx, target, descs)
}

// pushIndex pushes an index of descs, the platforms g's members published.
func (g *siteGroup) pushIndex(ctx context.Context, target oras.Target, descs []ocispec.Descriptor) (ocispec.Descriptor, error) {
	annotations := g.members[0].publication().annotations()
	delete(annotations, transfer.AnnotationPurl)
	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: descs[0].ArtifactType,
		Manifests:    descs,
		Annotations:  annotations,
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

// purls returns the purls of the components g's members publish.
func (g *siteGroup) purls() []string {
	purls := make([]string, 0, len(g.members))
	for _, member := range g.members {
		purls = append(purls, member.publication().component.PackageURL)
	}
	return purls
}

// componentPublisher publishes the components of its package, each at its
// own repository, which targets returns a target for.
type componentPublisher struct {
	publishOptions
	targets func(repository string) (oras.Target, error)
}

// publish publishes every component of p's package: it plans a publisher
// for each, grouped by site (see planGroups), and then runs each group
// (see publishGroup).
func (p componentPublisher) publish(ctx context.Context) ([]PublishedComponent, error) {
	groups, err := p.planGroups()
	if err != nil {
		return nil, err
	}

	var published []PublishedComponent
	for _, group := range groups {
		result, err := p.publishGroup(ctx, group)
		if err != nil {
			return nil, fmt.Errorf("publish at %w %s: %w", ErrComponentRepository, group.site.reference(), err)
		}
		published = append(published, result)
	}
	return published, nil
}

// planGroups returns the publisher of each of p's package's components
// (see newPublisher), grouped by the site each is published at (see
// componentSiteOf), in order, leaving out components without a purl.
// Components sharing a site must be the same content, published once, or
// platforms of one component: the same purl but for distinct "os" and
// "arch" qualifiers.
func (p componentPublisher) planGroups() ([]*siteGroup, error) {
	packageRepository := prefix.Repository(p.ref)
	var groups []*siteGroup
	byReference := map[string]*siteGroup{}
	for _, component := range splitByComponent(p.pkg.components, p.pkg.plans, p.pkg.layerDescs) {
		if component.component.PackageURL == "" {
			continue
		}
		purl, err := packageurl.FromString(component.component.PackageURL)
		if err != nil {
			return nil, fmt.Errorf("parse purl %q: %w", component.component.PackageURL, err)
		}
		site, err := componentSiteOf(packageRepository, purl)
		if err != nil {
			return nil, err
		}
		group, ok := byReference[site.reference()]
		if !ok {
			group = &siteGroup{site: site}
			byReference[site.reference()] = group
			groups = append(groups, group)
		}
		publication := componentPublication{
			publishOptions:  p.publishOptions,
			componentLayers: component,
			site:            site,
		}
		if err := group.add(newPublisher(publication)); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// publishGroup publishes group at its site, signs what its tag will
// name, and tags it, unless it's an image pinned by digest.
func (p componentPublisher) publishGroup(ctx context.Context, group *siteGroup) (PublishedComponent, error) {
	target, err := p.targets(group.site.repository)
	if err != nil {
		return PublishedComponent{}, err
	}
	tagged, err := group.publish(ctx, target)
	if err != nil {
		return PublishedComponent{}, err
	}

	reference := group.site.reference()
	if group.site.tag == "" {
		reference = group.site.repository + "@" + tagged.Digest.String()
	}
	if p.opts.Sign != nil {
		if err := p.opts.Sign(ctx, target, reference, tagged); err != nil {
			return PublishedComponent{}, fmt.Errorf("sign: %w", err)
		}
	}
	if group.site.tag != "" {
		if err := target.Tag(ctx, tagged, group.site.tag); err != nil {
			return PublishedComponent{}, fmt.Errorf("tag: %w", err)
		}
	}

	result := PublishedComponent{
		Purls:     group.purls(),
		Reference: reference,
		Digest:    tagged.Digest.String(),
	}
	return result, nil
}
