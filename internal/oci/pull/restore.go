package pull

import (
	"context"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
)

// layerGroup is one component's layers, purl's.
type layerGroup struct {
	purl string
	// manifestIndexes are where its layers are in the manifest's, in
	// order.
	manifestIndexes []int
}

// isComponentLayer reports whether desc is one of a component's own
// layers, a tar or a large file (see transfer.FileMediaType), naming
// its component's purl, which componentRestore restores together. Any
// other layer is foreign, written as-is by fetchLayer.
func isComponentLayer(desc ocispec.Descriptor) bool {
	if desc.Annotations[transfer.AnnotationPurl] == "" {
		return false
	}
	return desc.MediaType == transfer.LayerMediaType || desc.MediaType == transfer.FileMediaType
}

// groupLayers sorts descs into one group per component, in the order
// each first appears, and the indexes of the foreign layers left over.
// For example, these layers:
//
//	0: tar         pkg:oci/nginx@1.27
//	1: tar         pkg:huggingface/org/model@abc
//	2: foreign     (no purl, or another media type)
//	3: large file  pkg:huggingface/org/model@abc
//	4: tar         pkg:oci/nginx@1.27
//
// give the groups nginx [0 4] and model [1 3], and foreign [2].
func groupLayers(descs []ocispec.Descriptor) (groups []layerGroup, foreign []int) {
	groupIndex := map[string]int{}
	for index, desc := range descs {
		if !isComponentLayer(desc) {
			foreign = append(foreign, index)
			continue
		}
		purl := desc.Annotations[transfer.AnnotationPurl]
		position, seen := groupIndex[purl]
		if !seen {
			position = len(groups)
			groupIndex[purl] = position
			groups = append(groups, layerGroup{purl: purl})
		}
		groups[position].manifestIndexes = append(groups[position].manifestIndexes, index)
	}
	return groups, foreign
}

// descsIn returns g's layers out of descs, the package's.
func (g layerGroup) descsIn(descs []ocispec.Descriptor) []ocispec.Descriptor {
	groupDescs := make([]ocispec.Descriptor, 0, len(g.manifestIndexes))
	for _, index := range g.manifestIndexes {
		groupDescs = append(groupDescs, descs[index])
	}
	return groupDescs
}

// restoreOptions are what every restore of a pull shares: where layers
// come from and go, and how.
type restoreOptions struct {
	target  oras.ReadOnlyTarget
	dataDir string
	// componentsByPurl is the package's components, for each one's
	// manifest record (see recordComponentManifest).
	componentsByPurl map[string]cdx.Component
	// concurrency is how many components, or layers of one, restore at
	// once.
	concurrency int
	progress    transfer.ProgressFunc
}

// packageRestore restores a package's layers, descs.
type packageRestore struct {
	restoreOptions
	descs []ocispec.Descriptor
}

// newPackageRestore prepares the restore of descs, the layers of the
// package bom describes, into dataDir.
func newPackageRestore(target oras.ReadOnlyTarget, descs []ocispec.Descriptor, dataDir string, bom *cdx.BOM, concurrency int, progress transfer.ProgressFunc) *packageRestore {
	componentsByPurl := indexComponentsByPurl(bom)

	restore := packageRestore{
		restoreOptions: restoreOptions{
			target:           target,
			dataDir:          dataDir,
			componentsByPurl: componentsByPurl,
			concurrency:      concurrency,
			progress:         progress,
		},
		descs: descs,
	}
	return &restore
}

// restoreLayers restores r's layers into its data directory, up to its
// concurrency at once: each component's together (see groupLayers), then
// each foreign layer on its own, which packages bomify pushes don't have.
// It returns one RestoredLayer per layer, in the manifest's order.
func (r *packageRestore) restoreLayers(ctx context.Context) ([]RestoredLayer, error) {
	groups, foreign := groupLayers(r.descs)
	layers := make([]RestoredLayer, len(r.descs))
	if err := r.restoreComponents(ctx, groups, layers); err != nil {
		return nil, err
	}
	if err := r.fetchForeign(ctx, foreign, layers); err != nil {
		return nil, err
	}
	return layers, nil
}

// restoreComponents restores each of groups, a component's layers, into
// its directory (see componentRestore), filling in their places in layers.
func (r *packageRestore) restoreComponents(ctx context.Context, groups []layerGroup, layers []RestoredLayer) error {
	restored, err := parallel.Map(ctx, r.concurrency, groups, r.restoreGroup)
	if err != nil {
		return err
	}
	// Put each result back at its layer's place in the manifest, leaving
	// the foreign layers' places for fetchForeign.
	for groupIndex, componentLayers := range restored {
		group := groups[groupIndex]
		for position, layer := range componentLayers {
			layers[group.manifestIndexes[position]] = layer
		}
	}
	return nil
}

// restoreGroup restores one component from layerGroup, its layers,
// returning one RestoredLayer per layer, in the group's order.
func (r *packageRestore) restoreGroup(ctx context.Context, _ int, layerGroup layerGroup) ([]RestoredLayer, error) {
	restore := componentRestore{
		restoreOptions: r.restoreOptions,
		purl:           layerGroup.purl,
	}
	componentLayers, err := restore.run(ctx, layerGroup.descsIn(r.descs))
	if err != nil {
		return nil, fmt.Errorf("restore %s: %w", layerGroup.purl, err)
	}
	return componentLayers, nil
}

// fetchForeign writes the layers at foreign, their indexes, as-is (see
// fetchLayer), filling in their places in layers.
func (r *packageRestore) fetchForeign(ctx context.Context, foreign []int, layers []RestoredLayer) error {
	fetched, err := parallel.Map(ctx, r.concurrency, foreign, r.fetchForeignLayer)
	if err != nil {
		return err
	}
	// Fill in the places restoreComponents left.
	for position, layer := range fetched {
		layers[foreign[position]] = layer
	}
	return nil
}

// fetchForeignLayer writes the foreign layer at index in r's layers.
func (r *packageRestore) fetchForeignLayer(ctx context.Context, _ int, index int) (RestoredLayer, error) {
	layer, err := fetchLayer(ctx, r.target, r.descs[index], r.dataDir, r.progress)
	if err != nil {
		return RestoredLayer{}, fmt.Errorf("fetch layer %s: %w", r.descs[index].Digest, err)
	}
	return layer, nil
}

// componentRestore restores one component, purl's, from its layers to
// "<dataDir>/layers/<purl-hash>/", the directory `bomify build` would
// have written.
type componentRestore struct {
	restoreOptions
	purl string
}

// run restores the component from descs, its layers, returning one
// RestoredLayer per desc. Every layer goes into a staging directory, each
// verified against its digest, and the component's directory appears only
// once all are: a failed pull leaves nothing behind. No layer may write a
// file another already did, or outside the directory.
func (r componentRestore) run(ctx context.Context, descs []ocispec.Descriptor) ([]RestoredLayer, error) {
	layers, err := r.layers(descs)
	if err != nil {
		return nil, err
	}
	// The component already exists, from a build or an earlier pull: a
	// component's directory only ever appears whole, so it's kept, and
	// only its manifest record is filled in if missing.
	if r.exists() {
		return layers, r.recordManifest()
	}

	componentLayers, err := newComponentLayers(descs)
	if err != nil {
		return nil, err
	}
	write := func(dir string) error { return r.apply(ctx, dir, componentLayers) }
	if err := writeStaged(r.dir(), write); err != nil {
		return nil, err
	}
	return layers, r.recordManifest()
}

// dir is the component's directory.
func (r componentRestore) dir() string {
	return layout.ComponentLayer(r.dataDir, r.purl)
}

// layers returns the RestoredLayer run reports for each of descs.
func (r componentRestore) layers(descs []ocispec.Descriptor) ([]RestoredLayer, error) {
	layers := make([]RestoredLayer, 0, len(descs))
	for _, desc := range descs {
		hash, err := blobHash(desc)
		if err != nil {
			return nil, err
		}
		layer := RestoredLayer{
			Purl: r.purl,
			Hash: hash,
			Path: r.dir(),
		}
		layers = append(layers, layer)
	}
	return layers, nil
}

// exists reports whether the component's directory is already in place.
func (r componentRestore) exists() bool {
	info, err := os.Stat(r.dir())
	return err == nil && info.IsDir()
}

// recordManifest records the component, so a later build can reuse it.
func (r componentRestore) recordManifest() error {
	return recordComponentManifest(r.dataDir, r.componentsByPurl, r.purl)
}

// apply restores layers, a component's, into dir, up to r.concurrency at
// once, then checks its symlinks, which may point across layers (see
// fsutil.CheckSymlinks).
func (r componentRestore) apply(ctx context.Context, dir string, layers []componentLayer) error {
	restoreLayer := func(ctx context.Context, _ int, layer componentLayer) error {
		label := transfer.LayerLabel(r.purl, layer.descriptor().Digest.Encoded())
		return layer.restore(ctx, r.target, dir, label, r.progress)
	}
	if err := parallel.ForEach(ctx, r.concurrency, layers, restoreLayer); err != nil {
		return err
	}
	return fsutil.CheckSymlinks(dir)
}
