package pull

import (
	"context"
	"fmt"
	"os"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// isComponentLayer reports whether desc is one of a component's own
// layers, a tar or a large file (see transfer.FileMediaType), naming
// its component's purl, which componentRestore restores together. Any
// other layer is foreign, written as-is by foreignRestore.
func isComponentLayer(desc ocispec.Descriptor) bool {
	if desc.Annotations[transfer.AnnotationPurl] == "" {
		return false
	}
	return desc.MediaType == transfer.LayerMediaType || desc.MediaType == transfer.FileMediaType
}

// restoreOptions are what every restore of a pull shares: where layers
// come from and go, and how.
type restoreOptions struct {
	target  oras.ReadOnlyTarget
	dataDir string
	// concurrency is how many layerRestores run at once, and how many
	// layers download at once across all of them (see download).
	concurrency int
	// downloadSlots holds concurrency slots, one taken by each layer
	// downloading, shared by every restore of the pull.
	downloadSlots *semaphore.Weighted
	progress      transfer.ProgressFunc
}

// download runs fetch, one layer's download, once one of the pull's
// download slots is free. Every layer takes a slot, whichever restore it's
// part of, so components restoring at once, each downloading its layers
// at once, still download no more than concurrency layers in all.
func (o restoreOptions) download(ctx context.Context, fetch func() error) error {
	if err := o.downloadSlots.Acquire(ctx, 1); err != nil {
		return err
	}
	defer o.downloadSlots.Release(1)
	return fetch()
}

// layerRestore restores some of a package's layers: one component's,
// together (see componentRestore), or one foreign layer (see
// foreignRestore). run returns one RestoredLayer per layer.
type layerRestore interface {
	run(ctx context.Context) ([]RestoredLayer, error)
}

// packageRestore restores a package's layers, descs.
type packageRestore struct {
	restoreOptions
	descs []ocispec.Descriptor
	// componentsByPurl is the package's SBOM's components, to give each
	// componentRestore its own.
	componentsByPurl map[string]*cdx.Component
}

// newPackageRestore prepares the restore of descs, the layers of the
// package bom describes, into dataDir.
func newPackageRestore(target oras.ReadOnlyTarget, descs []ocispec.Descriptor, dataDir string, bom *cdx.BOM, concurrency int, progress transfer.ProgressFunc) *packageRestore {
	restore := packageRestore{
		restoreOptions: restoreOptions{
			target:        target,
			dataDir:       dataDir,
			concurrency:   concurrency,
			downloadSlots: semaphore.NewWeighted(int64(concurrency)),
			progress:      progress,
		},
		descs:            descs,
		componentsByPurl: indexComponentsByPurl(bom),
	}
	return &restore
}

// restoreLayers restores r's layers into its data directory (see
// restores), up to its concurrency at once. It returns one RestoredLayer
// per layer, each component's together.
func (r *packageRestore) restoreLayers(ctx context.Context) ([]RestoredLayer, error) {
	run := func(ctx context.Context, _ int, restore layerRestore) ([]RestoredLayer, error) {
		return restore.run(ctx)
	}
	restored, err := parallel.Map(ctx, r.concurrency, r.restores(), run)
	if err != nil {
		return nil, err
	}
	return slices.Concat(restored...), nil
}

// restores sorts r's layers into layerRestores, in the order each first
// appears: one per component, and one per foreign layer, which packages
// bomify pushes don't have. For example, these layers:
//
//	0: tar         pkg:oci/nginx@1.27
//	1: tar         pkg:huggingface/org/model@abc
//	2: foreign     (no purl, or another media type)
//	3: large file  pkg:huggingface/org/model@abc
//	4: tar         pkg:oci/nginx@1.27
//
// give the restores nginx [0 4], model [1 3], and foreign 2.
func (r *packageRestore) restores() []layerRestore {
	var restores []layerRestore
	components := map[string]*componentRestore{}
	for _, desc := range r.descs {
		if !isComponentLayer(desc) {
			restore := foreignRestore{
				restoreOptions: r.restoreOptions,
				desc:           desc,
			}
			restores = append(restores, restore)
			continue
		}
		purl := desc.Annotations[transfer.AnnotationPurl]
		component, seen := components[purl]
		if !seen {
			component = &componentRestore{
				restoreOptions: r.restoreOptions,
				purl:           purl,
				component:      r.componentsByPurl[purl],
			}
			components[purl] = component
			restores = append(restores, component)
		}
		component.descs = append(component.descs, desc)
	}
	return restores
}

// foreignRestore writes a foreign layer, desc, as-is (see fetchLayer).
type foreignRestore struct {
	restoreOptions
	desc ocispec.Descriptor
}

func (r foreignRestore) run(ctx context.Context) ([]RestoredLayer, error) {
	var layer RestoredLayer
	fetch := func() error {
		var err error
		layer, err = fetchLayer(ctx, r.target, r.desc, r.dataDir, r.progress)
		return err
	}
	if err := r.download(ctx, fetch); err != nil {
		return nil, fmt.Errorf("fetch layer %s: %w", r.desc.Digest, err)
	}
	return []RestoredLayer{layer}, nil
}

// componentRestore restores one component, purl's, from its layers, descs,
// to "<dataDir>/layers/<purl-hash>/", the directory `bomify build` would
// have written.
type componentRestore struct {
	restoreOptions
	purl  string
	descs []ocispec.Descriptor
	// component is the package's SBOM's entry for purl, or nil if it has
	// none (see recordManifest).
	component *cdx.Component
}

// run restores the component, returning one RestoredLayer per layer.
// Every layer goes into a staging directory, each verified against its
// digest, and the component's directory appears only once all are: a
// failed pull leaves nothing behind. No layer may write a file another
// already did, or outside the directory.
func (r componentRestore) run(ctx context.Context) (layers []RestoredLayer, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("restore %s: %w", r.purl, err)
		}
	}()

	layers, err = r.layers()
	if err != nil {
		return nil, err
	}
	// The component already exists, from a build or an earlier pull: a
	// component's directory only ever appears whole, so it's kept, and
	// only its manifest record is filled in if missing.
	if r.exists() {
		return layers, r.recordManifest()
	}

	componentLayers, err := newComponentLayers(r.descs)
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

// layers returns the RestoredLayer run reports for each of r's layers.
func (r componentRestore) layers() ([]RestoredLayer, error) {
	layers := make([]RestoredLayer, 0, len(r.descs))
	for _, desc := range r.descs {
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

// recordManifest records the component's SBOM entry as its manifest, so a
// later `bomify build` can reuse it instead of re-invoking a plugin. No
// hash is computed, as the entry already declares one, and nothing is
// recorded for a component the SBOM lacks.
func (r componentRestore) recordManifest() error {
	if r.component == nil {
		return nil
	}
	return plugin.WriteManifest(r.dataDir, *r.component, pluginlib.Hash{})
}

// apply restores layers, a component's, into dir, each as soon as a
// download slot is free (see download), then checks its symlinks, which
// may point across layers (see fsutil.CheckSymlinks).
func (r componentRestore) apply(ctx context.Context, dir string, layers []componentLayer) error {
	restoreLayer := func(ctx context.Context, _ int, layer componentLayer) error {
		label := transfer.LayerLabel(r.purl, layer.descriptor().Digest.Encoded())
		fetch := func() error { return layer.restore(ctx, r.target, dir, label, r.progress) }
		return r.download(ctx, fetch)
	}
	// No limit of its own: download is what bounds the layers.
	if err := parallel.ForEach(ctx, 0, layers, restoreLayer); err != nil {
		return err
	}
	return fsutil.CheckSymlinks(dir)
}
