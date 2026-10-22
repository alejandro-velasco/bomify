package pull

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// restoreOptions are what every restore of a pull shares: where layers
// come from and go, and how.
type restoreOptions struct {
	target  oras.ReadOnlyTarget
	dataDir string
	// concurrency is how many componentRestores run at once, and how many
	// layers download at once across all of them (see download).
	concurrency int
	// downloadSlots holds concurrency slots, one taken by each layer
	// downloading, shared by every restore of the pull.
	downloadSlots *semaphore.Weighted
	progress      transfer.ProgressFunc
}

// newRestoreOptions returns the restoreOptions of a pull from target into
// dataDir.
func newRestoreOptions(target oras.ReadOnlyTarget, dataDir string, concurrency int, progress transfer.ProgressFunc) restoreOptions {
	options := restoreOptions{
		target:        target,
		dataDir:       dataDir,
		concurrency:   concurrency,
		downloadSlots: semaphore.NewWeighted(int64(concurrency)),
		progress:      progress,
	}
	return options
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

// packageRestore restores a package's components, from their manifests,
// descs.
type packageRestore struct {
	restoreOptions
	descs []ocispec.Descriptor
	// files is the package's files map, of the components restored file by
	// file.
	files transfer.Files
	// componentsByPurl is the package's SBOM's components, to give each
	// componentRestore its own.
	componentsByPurl map[string]*cdx.Component
}

// newPackageRestore prepares the restore of descs, the component manifests
// of the package bom describes, whose files map is files, into dataDir.
func newPackageRestore(target oras.ReadOnlyTarget, descs []ocispec.Descriptor, files transfer.Files, dataDir string, bom *cdx.BOM, concurrency int, progress transfer.ProgressFunc) *packageRestore {
	restore := packageRestore{
		restoreOptions:   newRestoreOptions(target, dataDir, concurrency, progress),
		descs:            descs,
		files:            files,
		componentsByPurl: indexComponentsByPurl(bom),
	}
	return &restore
}

// restoreComponents restores r's components into its data directory (see
// componentRestore), up to its concurrency at once, in its index's order.
// It fails before restoring anything if the index names a component twice.
func (r *packageRestore) restoreComponents(ctx context.Context) ([]RestoredComponent, error) {
	restores := make([]componentRestore, 0, len(r.descs))
	seen := map[string]bool{}
	for _, desc := range r.descs {
		purl := desc.Annotations[transfer.AnnotationPurl]
		if seen[purl] {
			return nil, fmt.Errorf("package index names %s twice", purl)
		}
		seen[purl] = true
		files, ok := r.files.Component(purl)
		if !ok {
			return nil, fmt.Errorf("package's files map doesn't lay out %s", purl)
		}
		restore := componentRestore{
			restoreOptions: r.restoreOptions,
			manifest:       desc,
			files:          files,
			component:      r.componentsByPurl[purl],
		}
		restores = append(restores, restore)
	}

	run := func(ctx context.Context, _ int, restore componentRestore) (RestoredComponent, error) {
		return restore.run(ctx)
	}
	return parallel.Map(ctx, r.concurrency, restores, run)
}

// componentRestore restores one component, whose manifest is manifest,
// from its files in its package's files map, to
// "<dataDir>/layers/<purl-hash>/", the directory `bomify build` would
// have written.
type componentRestore struct {
	restoreOptions
	manifest ocispec.Descriptor
	files    transfer.ComponentFiles
	// component is the package's SBOM's entry for the component, or nil if
	// it has none (see recordManifest).
	component *cdx.Component
}

// run restores the component. Every file goes into a staging directory,
// each verified against its digest, and the component's directory appears
// only once all are: a failed pull leaves nothing behind.
func (r componentRestore) run(ctx context.Context) (restored RestoredComponent, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("restore %s: %w", r.files.Purl, err)
		}
	}()

	restored = RestoredComponent{
		Purl:   r.files.Purl,
		Digest: r.manifest.Digest.String(),
		Path:   r.dir(),
	}
	// The component already exists, from a build or an earlier pull: a
	// component's directory only ever appears whole, so it's kept, and
	// only its manifest record is filled in if missing.
	if r.exists() {
		return restored, r.recordManifest()
	}

	write := func(dir string) error { return r.apply(ctx, dir) }
	if err := writeStaged(r.dir(), write); err != nil {
		return RestoredComponent{}, err
	}
	return restored, r.recordManifest()
}

// dir is the component's directory.
func (r componentRestore) dir() string {
	return layout.ComponentLayer(r.dataDir, r.files.Purl)
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

// apply restores the component's files into dir, each as soon as a
// download slot is free (see download).
func (r componentRestore) apply(ctx context.Context, dir string) error {
	restore := func(ctx context.Context, _ int, file transfer.FileBlob) error {
		fetch := func() error { return r.restoreFile(ctx, dir, file) }
		return r.download(ctx, fetch)
	}
	// No limit of its own: download is what bounds the files.
	return parallel.ForEach(ctx, 0, r.files.Files, restore)
}

// restoreFile writes file under dir through an os.Root of dir, so it
// can't be led outside, failing if it exists, or unless its blob matches
// its digest. transfer.FetchFiles has checked its path is inside dir.
func (r componentRestore) restoreFile(ctx context.Context, dir string, file transfer.FileBlob) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	path := filepath.FromSlash(file.Path)
	if err := root.MkdirAll(filepath.Dir(path), transfer.DirPerm); err != nil {
		return fmt.Errorf("create %s: %w", file.Path, err)
	}
	written, err := root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(file.Mode))
	if err != nil {
		return fmt.Errorf("create %s: %w", file.Path, err)
	}
	defer written.Close()

	desc := file.Descriptor()
	rc, err := r.target.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", desc.Digest, err)
	}
	defer rc.Close()

	label := transfer.LayerLabel(r.files.Purl, desc.Digest.Encoded())
	pw := r.progress(label, desc.Size)
	defer pw.Close()

	verified := content.NewVerifyReader(rc, desc)
	reader := io.TeeReader(verified, pw)
	if _, err := io.Copy(written, reader); err != nil {
		return fmt.Errorf("%s: %w", desc.Digest, err)
	}
	if err := verified.Verify(); err != nil {
		return fmt.Errorf("verify %s: %w", desc.Digest, err)
	}
	return written.Close()
}
