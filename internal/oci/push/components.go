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
func (c *componentLayers) dir() string {
	return c.plans[0].directory()
}

// sameContent reports whether c and other were pushed as the same
// layers.
func (c *componentLayers) sameContent(other *componentLayers) bool {
	return slices.EqualFunc(c.descs, other.descs, func(a, b ocispec.Descriptor) bool { return a.Digest == b.Digest })
}

// splitByComponent groups plans, pushed as descs, by component, in
// components' order.
func splitByComponent(components []cdx.Component, plans []layerPlan, descs []ocispec.Descriptor) []*componentLayers {
	byPurl := make(map[string]*componentLayers, len(components))
	grouped := make([]*componentLayers, 0, len(components))
	for _, component := range components {
		if _, seen := byPurl[component.PackageURL]; seen {
			continue
		}
		entry := &componentLayers{component: component}
		grouped = append(grouped, entry)
		byPurl[component.PackageURL] = entry
	}
	// Give each layer, plans[index] pushed as descs[index], to the entry of
	// the component that owns it, keeping the layers' manifest order.
	for index, plan := range plans {
		entry := byPurl[plan.owner().PackageURL]
		entry.plans = append(entry.plans, plan)
		entry.descs = append(entry.descs, descs[index])
	}
	return grouped
}

// publishComponents publishes each component of pkg, pushed as ref but not
// yet tagged, at its own repository beside the package's, which
// opts.ComponentTarget gives a target for: it plans what's published at
// each site (see planSites), and then publishes each (see sitePublish.run).
func publishComponents(ctx context.Context, pkg *pushedPackage, ref string, opts transfer.Options) ([]PublishedComponent, error) {
	options := publishOptions{
		pkg:  pkg,
		ref:  ref,
		opts: opts,
	}
	sites, err := planSites(options)
	if err != nil {
		return nil, err
	}

	published := make([]PublishedComponent, 0, len(sites))
	for _, publish := range sites {
		result, err := publish.run(ctx)
		if err != nil {
			return nil, fmt.Errorf("publish at %w %s: %w", ErrComponentRepository, publish.site.reference(), err)
		}
		published = append(published, result)
	}
	return published, nil
}

// publishOptions are what every publish of a push's components shares: the
// package they're published from, pushed as ref but not yet tagged, and
// how.
type publishOptions struct {
	pkg  *pushedPackage
	ref  string
	opts transfer.Options
}

// annotations returns the annotations everything published for the
// package's components shares: the package's digest, and its created
// time, so publishing an unchanged package gives the same digests.
func (o publishOptions) annotations() map[string]string {
	annotations := map[string]string{
		ocispec.AnnotationCreated: o.pkg.created,
		AnnotationPackageDigest:   o.pkg.desc.Digest.String(),
	}
	return annotations
}

// pushBlob makes desc available in target, from the content open returns:
// mounted from the package's repository if the package pushed it as one
// of its layers, as it does a large file, and target can mount, and
// otherwise pushed.
func (o publishOptions) pushBlob(ctx context.Context, target oras.Target, desc ocispec.Descriptor, open func() (io.ReadCloser, error), label string) error {
	mountTarget, canMount := target.(transfer.MountTarget)
	pushed := slices.ContainsFunc(o.pkg.layerDescs, func(layer ocispec.Descriptor) bool {
		return layer.Digest == desc.Digest
	})
	if canMount && pushed {
		reference, err := orasregistry.ParseReference(prefix.Repository(o.ref))
		if err == nil {
			return transfer.MountBlob(ctx, mountTarget, desc, reference.Repository, open, label, o.opts.Progress)
		}
	}
	content, err := open()
	if err != nil {
		return err
	}
	defer content.Close()
	return transfer.PushBlob(ctx, target, desc, content, label, o.opts.Progress)
}

// planSites plans the publish of each of the package's components with a
// purl at its site (see componentSiteOf), by a componentPublisher for its
// kind, those sharing a site together, in order. Components sharing a site
// must be the same content, published once, or platforms of one
// component: the same purl but for distinct "os" and "arch" qualifiers.
func planSites(options publishOptions) ([]*sitePublish, error) {
	packageRepository := prefix.Repository(options.ref)
	var sites []*sitePublish
	byReference := map[string]*sitePublish{}
	for _, component := range options.pkg.byComponent {
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

		publish, planned := byReference[site.reference()]
		if !planned {
			publish = &sitePublish{
				publishOptions: options,
				site:           site,
			}
			byReference[site.reference()] = publish
			sites = append(sites, publish)
		}
		publication := componentPublication{
			publishOptions:  options,
			componentLayers: component,
			site:            site,
		}
		if err := publish.add(newComponentPublisher(publication)); err != nil {
			return nil, err
		}
	}
	return sites, nil
}

// sitePublish publishes the components at one site: one, or each platform
// of one, as an index.
type sitePublish struct {
	publishOptions
	site    componentSite
	members []componentPublisher
}

// add adds member to s, unless it publishes the same content as a member
// already there.
func (s *sitePublish) add(member componentPublisher) error {
	added := member.publication()
	for _, existing := range s.members {
		other := existing.publication()
		if other.sameContent(added.componentLayers) {
			return nil
		}
		platforms := other.site.hasPlatform() && added.site.hasPlatform() && (other.site.os != added.site.os || other.site.arch != added.site.arch)
		if other.site.unqualified != added.site.unqualified || !platforms {
			return fmt.Errorf("%s and %s would both be published at %s, with different content", other.component.PackageURL, added.component.PackageURL, s.site.reference())
		}
	}
	s.members = append(s.members, member)
	return nil
}

// run publishes s's members at its site (see publish), signs what the
// site names, and tags it, unless it's an image pinned by digest.
func (s *sitePublish) run(ctx context.Context) (PublishedComponent, error) {
	target, err := s.opts.ComponentTarget(s.site.repository)
	if err != nil {
		return PublishedComponent{}, err
	}
	tagged, err := s.publish(ctx, target)
	if err != nil {
		return PublishedComponent{}, err
	}

	reference := s.site.reference()
	if s.site.tag == "" {
		reference = s.site.repository + "@" + tagged.Digest.String()
	}
	if s.opts.Sign != nil {
		if err := s.opts.Sign(ctx, target, reference, tagged); err != nil {
			return PublishedComponent{}, fmt.Errorf("sign: %w", err)
		}
	}
	if s.site.tag != "" {
		if err := target.Tag(ctx, tagged, s.site.tag); err != nil {
			return PublishedComponent{}, fmt.Errorf("tag: %w", err)
		}
	}

	purls := make([]string, 0, len(s.members))
	for _, member := range s.members {
		purls = append(purls, member.publication().component.PackageURL)
	}
	result := PublishedComponent{
		Purls:     purls,
		Reference: reference,
		Digest:    tagged.Digest.String(),
	}
	return result, nil
}

// publish pushes each of s's members to target, returning the descriptor
// of what s's site names: its one member's manifest, or an index of every
// member's, each for its platform.
func (s *sitePublish) publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	manifests := make([]ocispec.Descriptor, 0, len(s.members))
	for _, member := range s.members {
		manifest, err := member.publish(ctx, target)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		if len(s.members) > 1 {
			site := member.publication().site
			manifest.Platform = &ocispec.Platform{OS: site.os, Architecture: site.arch}
		}
		manifests = append(manifests, manifest)
	}
	if len(manifests) == 1 {
		return manifests[0], nil
	}

	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: manifests[0].ArtifactType,
		Manifests:    manifests,
		Annotations:  s.annotations(),
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

// componentPublisher publishes one component at its site, in its kind's
// format: an imagePublisher, chartPublisher, or artifactPublisher (see
// newComponentPublisher). publish pushes it to target, returning its
// manifest's descriptor; publication is what it publishes.
type componentPublisher interface {
	publication() componentPublication
	publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error)
}

// componentPublication is what a componentPublisher publishes: a
// component of the package, as Push pushed its layers, at its site.
type componentPublication struct {
	publishOptions
	*componentLayers
	site componentSite
}

func (c componentPublication) publication() componentPublication {
	return c
}

// annotations returns the annotations of what's published for c's
// component: the ones every component's share (see
// publishOptions.annotations), and its purl.
func (c componentPublication) annotations() map[string]string {
	annotations := c.publishOptions.annotations()
	annotations[transfer.AnnotationPurl] = c.component.PackageURL
	return annotations
}

// newComponentPublisher returns the publisher of publication, by its
// component's purl type: an image as it is (see imagePublisher), a chart
// as Helm stores one (see chartPublisher), and anything else as an
// artifact of its files (see artifactPublisher).
func newComponentPublisher(publication componentPublication) componentPublisher {
	switch publication.site.kind {
	case packageurl.TypeOCI, packageurl.TypeDocker:
		return imagePublisher{publication}
	case packageurl.TypeHelm:
		return chartPublisher{publication}
	default:
		return artifactPublisher{publication}
	}
}
