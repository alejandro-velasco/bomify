package push

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
	"github.com/alejandro-velasco/bomify/internal/prefix"
)

// What Push publishes for a component at its own repository, unless it's
// a model: an artifact of ComponentArtifactType, its small files in one
// layer of ComponentTarGzMediaType, its large files in layers of
// transfer.FilePartMediaType, and the artifact annotated with
// AnnotationPackageDigest, the package it was published with.
const (
	ComponentArtifactType   = "application/vnd.bomify.component.v1+json"
	ComponentTarGzMediaType = "application/vnd.bomify.component.layer.v1.tar+gzip"
	AnnotationPackageDigest = "land.bomify.package.digest"
)

// ModelPack's types and annotations
// (https://github.com/modelpack/model-spec), which a
// machine-learning-model component is published with instead.
const (
	ModelArtifactType       = "application/vnd.cncf.model.manifest.v1+json"
	modelConfigMediaType    = "application/vnd.cncf.model.config.v1+json"
	modelWeightMediaType    = "application/vnd.cncf.model.weight.v1.raw"
	modelConfigTarMediaType = "application/vnd.cncf.model.weight.config.v1.tar+gzip"
	annotationModelFilepath = "org.cncf.model.filepath"
	annotationModelUntested = "org.cncf.model.file.mediatype.untested"
)

// The annotations `oras pull` unpacks a gzipped tar by: into the
// directory its title names, checking the uncompressed tar's digest.
const (
	annotationOrasUnpack    = "io.deis.oras.content.unpack"
	annotationOrasTarDigest = "io.deis.oras.content.digest"
)

// componentRepositoryLabel ends a blob's label in progress output when
// it's pushed to a component's repository.
const componentRepositoryLabel = " (component repository)"

// skippedKinds are the purl types Push doesn't publish at a repository of
// their own yet: images and charts, which need their own artifact
// formats.
var skippedKinds = []string{"oci", "docker", "helm"}

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

// ComponentRepositoryError is the error of publishing a component at its
// own repository, which a registry that can't host nested repositories,
// or doesn't create them on push, fails.
type ComponentRepositoryError struct {
	Reference string
	Err       error
}

func (e *ComponentRepositoryError) Error() string {
	return fmt.Sprintf("publish at %s: %v", e.Reference, e.Err)
}

func (e *ComponentRepositoryError) Unwrap() error { return e.Err }

// componentLayers are a component of a pushed package, and the layers
// Push pushed for it: plans, pushed as descs.
type componentLayers struct {
	component cdx.Component
	plans     []layerPlan
	descs     []ocispec.Descriptor
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
		entry := byPurl[plan.component.PackageURL]
		entry.plans = append(entry.plans, plan)
		entry.descs = append(entry.descs, descs[index])
	}
	return grouped
}

// siteGroup is the components published at one site: one, or each
// platform of an index.
type siteGroup struct {
	site    componentSite
	members []componentLayers
	sites   []componentSite
}

// planSites groups components by the site each is published at (see
// componentSiteOf), in order, leaving out skippedKinds and components
// without a purl. Components sharing a site must be the same content,
// published once, or platforms of one component: the same purl but for
// distinct "os" and "arch" qualifiers.
func planSites(packageRepository string, components []componentLayers) ([]*siteGroup, error) {
	var groups []*siteGroup
	byReference := map[string]*siteGroup{}
	for _, component := range components {
		purl := component.component.PackageURL
		if purl == "" || isSkippedKind(purl) {
			continue
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
		if err := group.add(component, site); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// add adds component, published at site, to g, unless it's the same
// content as a member already there.
func (g *siteGroup) add(component componentLayers, site componentSite) error {
	for index, member := range g.members {
		if member.sameContent(component) {
			return nil
		}
		other := g.sites[index]
		platforms := other.hasPlatform() && site.hasPlatform() && (other.os != site.os || other.arch != site.arch)
		if other.unqualified != site.unqualified || !platforms {
			return fmt.Errorf("%s and %s would both be published at %s, with different content", member.component.PackageURL, component.component.PackageURL, site.reference())
		}
	}
	g.members = append(g.members, component)
	g.sites = append(g.sites, site)
	return nil
}

// isSkippedKind reports whether purl's type is one of skippedKinds.
func isSkippedKind(purl string) bool {
	for _, kind := range skippedKinds {
		if strings.HasPrefix(purl, "pkg:"+kind+"/") {
			return true
		}
	}
	return false
}

// componentPublisher publishes the components of pkg, a package pushed
// as ref but not yet tagged, each at its own repository.
type componentPublisher struct {
	pkg     *pushedPackage
	ref     string
	targets func(repository string) (oras.Target, error)
	opts    transfer.Options
}

// publish publishes every component of p's package at its site (see
// planSites): each as an artifact of its files (see publishArtifact), and
// platforms sharing a site as an index of theirs, signed with
// opts.Sign, and then tagged.
func (p componentPublisher) publish(ctx context.Context) ([]PublishedComponent, error) {
	components := splitByComponent(p.pkg.components, p.pkg.plans, p.pkg.layerDescs)
	groups, err := planSites(prefix.Repository(p.ref), components)
	if err != nil {
		return nil, err
	}

	var published []PublishedComponent
	for _, group := range groups {
		reference := group.site.reference()
		result, err := p.publishGroup(ctx, group)
		if err != nil {
			return nil, &ComponentRepositoryError{Reference: reference, Err: err}
		}
		published = append(published, result)
	}
	return published, nil
}

// publishGroup publishes group at its site, signs what its tag will
// name, and tags it.
func (p componentPublisher) publishGroup(ctx context.Context, group *siteGroup) (PublishedComponent, error) {
	target, err := p.targets(group.site.repository)
	if err != nil {
		return PublishedComponent{}, err
	}

	var descs []ocispec.Descriptor
	var purls []string
	for index, member := range group.members {
		desc, err := p.publishArtifact(ctx, target, member)
		if err != nil {
			return PublishedComponent{}, err
		}
		if len(group.members) > 1 {
			site := group.sites[index]
			desc.Platform = &ocispec.Platform{OS: site.os, Architecture: site.arch}
		}
		descs = append(descs, desc)
		purls = append(purls, member.component.PackageURL)
	}
	tagged := descs[0]
	if len(descs) > 1 {
		if tagged, err = p.pushIndex(ctx, target, descs, group.members[0].component); err != nil {
			return PublishedComponent{}, err
		}
	}

	reference := group.site.reference()
	if p.opts.Sign != nil {
		if err := p.opts.Sign(ctx, target, reference, tagged); err != nil {
			return PublishedComponent{}, fmt.Errorf("sign: %w", err)
		}
	}
	if err := target.Tag(ctx, tagged, group.site.tag); err != nil {
		return PublishedComponent{}, fmt.Errorf("tag: %w", err)
	}

	result := PublishedComponent{
		Purls:     purls,
		Reference: reference,
		Digest:    tagged.Digest.String(),
	}
	return result, nil
}

// annotations returns the annotations of what's published for
// component: its purl, the package's digest, and the package's created
// time, so publishing an unchanged package gives the same digests.
func (p componentPublisher) annotations(component cdx.Component) map[string]string {
	annotations := map[string]string{
		ocispec.AnnotationCreated: createdAnnotation(p.pkg.bom),
		transfer.AnnotationPurl:   component.PackageURL,
		AnnotationPackageDigest:   p.pkg.desc.Digest.String(),
	}
	return annotations
}

// pushIndex pushes an index of descs, the platforms of component.
func (p componentPublisher) pushIndex(ctx context.Context, target oras.Target, descs []ocispec.Descriptor, component cdx.Component) (ocispec.Descriptor, error) {
	annotations := p.annotations(component)
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

// publishArtifact pushes component's files to target as an artifact
// `oras pull` writes out as they are (see artifactLayers), returning its
// manifest's descriptor. A model is a ModelPack artifact.
func (p componentPublisher) publishArtifact(ctx context.Context, target oras.Target, component componentLayers) (ocispec.Descriptor, error) {
	isModel := component.component.Type == cdx.ComponentTypeMachineLearningModel
	layers, diffIDs, err := p.pushArtifactLayers(ctx, target, component, isModel)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	packOpts := oras.PackManifestOptions{
		Layers:              layers,
		ManifestAnnotations: p.annotations(component.component),
	}
	artifactType := ComponentArtifactType
	if isModel {
		artifactType = ModelArtifactType
		config, err := p.pushModelConfig(ctx, target, component.component, diffIDs)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		packOpts.ConfigDescriptor = &config
	}
	desc, err := oras.PackManifest(ctx, target, oras.PackManifestVersion1_1, artifactType, packOpts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack manifest: %w", err)
	}
	desc.ArtifactType = artifactType
	return desc, nil
}

// pushArtifactLayers pushes component's layers as an artifact's (see
// publishArtifact), up to opts.Concurrency at once: its small files as
// one gzipped tar, titled "." and annotated for `oras pull` to unpack
// where it's pulled to, then each large file's layers, the package's own
// blobs, titled with their path when the file is one layer, as all but
// those past transfer.MaxLayerSize are. It returns them with their
// uncompressed digests, in order.
func (p componentPublisher) pushArtifactLayers(ctx context.Context, target oras.Target, component componentLayers, isModel bool) ([]ocispec.Descriptor, []digest.Digest, error) {
	var smallFiles []transfer.TarFile
	var dir string
	var parts []int
	for index, plan := range component.plans {
		dir = plan.dir
		if plan.part != nil {
			parts = append(parts, index)
			continue
		}
		smallFiles = append(smallFiles, plan.tarFiles...)
	}

	var layers []ocispec.Descriptor
	var diffIDs []digest.Digest
	if len(smallFiles) > 0 {
		layer, tarDigest, err := p.pushTarGz(ctx, target, component.component, dir, smallFiles, isModel)
		if err != nil {
			return nil, nil, err
		}
		layers = append(layers, layer)
		diffIDs = append(diffIDs, tarDigest)
	}

	pushPart := func(ctx context.Context, _ int, index int) (ocispec.Descriptor, error) {
		plan := component.plans[index]
		desc := artifactPart(component.descs[index], plan, isModel)
		file, err := os.Open(filepath.Join(plan.dir, filepath.FromSlash(plan.part.Path)))
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		defer file.Close()
		section := io.NewSectionReader(file, plan.part.Offset, plan.part.length)
		label := transfer.PartLabel(plan.component.PackageURL, plan.part.Path, plan.part.number, plan.part.count) + componentRepositoryLabel
		if err := transfer.PushBlob(ctx, target, desc, section, label, p.opts.Progress); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", plan.part.Path, err)
		}
		return desc, nil
	}
	partLayers, err := parallel.Map(ctx, p.opts.Concurrency, parts, pushPart)
	if err != nil {
		return nil, nil, err
	}
	for _, layer := range partLayers {
		layers = append(layers, layer)
		diffIDs = append(diffIDs, layer.Digest)
	}
	return layers, diffIDs, nil
}

// artifactPart returns the descriptor of a large file's layer in a
// component's artifact: packaged, its descriptor in the package, titled
// with the file's path when it's the file's only layer, so `oras pull`
// writes it out. A model's is a ModelPack weight.
func artifactPart(packaged ocispec.Descriptor, plan layerPlan, isModel bool) ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType:   packaged.MediaType,
		Digest:      packaged.Digest,
		Size:        packaged.Size,
		Annotations: plan.part.Annotations(plan.component.PackageURL),
	}
	if plan.part.count == 1 {
		desc.Annotations[ocispec.AnnotationTitle] = plan.part.Path
	}
	if isModel {
		desc.MediaType = modelWeightMediaType
		desc.Annotations[annotationModelFilepath] = plan.part.Path
		// Large isn't proof of a weight.
		desc.Annotations[annotationModelUntested] = "true"
	}
	return desc
}

// pushTarGz pushes files, of component's directory dir, as one gzipped
// tar `oras pull` unpacks into the directory it pulls to, returning its
// descriptor and the uncompressed tar's digest.
func (p componentPublisher) pushTarGz(ctx context.Context, target oras.Target, component cdx.Component, dir string, files []transfer.TarFile, isModel bool) (ocispec.Descriptor, digest.Digest, error) {
	tmp, err := os.CreateTemp("", "bomify-push-component-*.tar.gz")
	if err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	compressedHasher, tarHasher := sha256.New(), sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(tmp, compressedHasher))
	if err := transfer.WriteTarTree(dir, files, io.MultiWriter(gz, tarHasher)); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("archive %s: %w", dir, err)
	}
	if err := gz.Close(); err != nil {
		return ocispec.Descriptor{}, "", err
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return ocispec.Descriptor{}, "", err
	}
	hash := hex.EncodeToString(compressedHasher.Sum(nil))
	tarDigest := digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(tarHasher.Sum(nil)))

	desc := ocispec.Descriptor{
		MediaType: ComponentTarGzMediaType,
		Digest:    digest.NewDigestFromEncoded(digest.SHA256, hash),
		Size:      size,
		Annotations: map[string]string{
			ocispec.AnnotationTitle: ".",
			annotationOrasUnpack:    "true",
			annotationOrasTarDigest: tarDigest.String(),
			transfer.AnnotationPurl: component.PackageURL,
		},
	}
	if isModel {
		desc.MediaType = modelConfigTarMediaType
		// Small files are a model's configuration, tokenizer, and docs,
		// mixed.
		desc.Annotations[annotationModelUntested] = "true"
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return ocispec.Descriptor{}, "", err
	}
	label := transfer.Label(component.PackageURL, hash) + componentRepositoryLabel
	if err := transfer.PushBlob(ctx, target, desc, tmp, label, p.opts.Progress); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("push layer: %w", err)
	}
	return desc, tarDigest, nil
}

// modelConfig is a ModelPack model's config: what it is, and the
// uncompressed digests of its layers.
type modelConfig struct {
	Descriptor modelDescriptor `json:"descriptor"`
	Config     struct{}        `json:"config"`
	ModelFS    modelFS         `json:"modelfs"`
}

type modelDescriptor struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type modelFS struct {
	Type    string          `json:"type"`
	DiffIDs []digest.Digest `json:"diffIds"`
}

// pushModelConfig pushes component's ModelPack config, for layers whose
// uncompressed digests are diffIDs.
func (p componentPublisher) pushModelConfig(ctx context.Context, target oras.Target, component cdx.Component, diffIDs []digest.Digest) (ocispec.Descriptor, error) {
	config := modelConfig{
		Descriptor: modelDescriptor{
			Name:    component.Name,
			Version: component.Version,
		},
		ModelFS: modelFS{
			Type:    "layers",
			DiffIDs: append([]digest.Digest{}, diffIDs...),
		},
	}
	data, err := json.Marshal(config)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc, err := transfer.PushBytes(ctx, target, data, modelConfigMediaType, "model config", p.opts.Progress)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push config: %w", err)
	}
	return desc, nil
}
