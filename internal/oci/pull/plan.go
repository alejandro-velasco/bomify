package pull

import (
	"archive/tar"
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// componentPlan is how a component's layers restore, checked before any
// of them is downloaded (see planComponent).
type componentPlan struct {
	// files are the large files its parts make up, created before any
	// layer restores.
	files []partFile
	// transfers restore its layers, one per layer: its tars, then each
	// file's parts, by offset.
	transfers []layerTransfer
}

// layerTransfer is one of a component's layers, which restore writes into
// dir, verifying it against its digest as it streams.
type layerTransfer interface {
	// label names the layer, of purl's component, in progress output.
	label(purl string) string
	restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error
}

// layerBlob is a layer's blob: what tarLayer and partLayer share.
type layerBlob struct {
	desc ocispec.Descriptor
}

// fetch streams b's content to consume, with its progress bar, and fails
// unless all of it matches its digest, including anything consume leaves
// unread, such as a tar's padding after its end-of-archive marker.
func (b layerBlob) fetch(ctx context.Context, target oras.ReadOnlyTarget, label string, progress transfer.ProgressFunc, consume func(io.Reader) error) error {
	rc, err := target.Fetch(ctx, b.desc)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", b.desc.Digest, err)
	}
	defer rc.Close()

	pw := progress(label, b.desc.Size)
	defer pw.Close()

	verified := content.NewVerifyReader(rc, b.desc)
	reader := io.TeeReader(verified, pw)
	if err := consume(reader); err != nil {
		return fmt.Errorf("%s: %w", b.desc.Digest, err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("download %s: %w", b.desc.Digest, err)
	}
	if err := verified.Verify(); err != nil {
		return fmt.Errorf("verify %s: %w", b.desc.Digest, err)
	}
	return nil
}

// tarLayer is a tar layer, unpacked into the component's directory.
type tarLayer struct {
	layerBlob
}

// restore unpacks the tar into dir. An entry naming a file that already
// exists fails it (see transfer.ExtractTarExclusive).
func (t tarLayer) restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error {
	unpack := func(r io.Reader) error {
		if err := transfer.ExtractTarExclusive(tar.NewReader(r), dir); err != nil {
			return fmt.Errorf("unpack: %w", err)
		}
		return nil
	}
	return t.fetch(ctx, target, label, progress, unpack)
}

// partLayer is one piece of a partFile: a file part layer, written into
// its file at its offset.
type partLayer struct {
	layerBlob
	path   string
	offset int64
	// number is which of its file's count parts this is, from 1, once
	// checkCoverage has numbered it.
	number, count int
}

func (p partLayer) label(purl string) string {
	return transfer.PartLabel(purl, p.path, p.number, p.count)
}

func (t tarLayer) label(purl string) string {
	return transfer.Label(purl, t.desc.Digest.Encoded())
}

// restore writes the part into its file under dir, which createFiles
// made, at its offset.
func (p partLayer) restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error {
	file, err := os.OpenFile(filepath.Join(dir, filepath.FromSlash(p.path)), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	writeAtOffset := func(r io.Reader) error {
		_, err := io.Copy(io.NewOffsetWriter(file, p.offset), r)
		return err
	}
	if err := p.fetch(ctx, target, label, progress, writeAtOffset); err != nil {
		return err
	}
	return file.Close()
}

// partFile is a large file split across file part layers (see
// transfer.FilePartMediaType), which its partLayer pieces rebuild.
type partFile struct {
	// path is its "/"-separated path in the component's directory.
	path string
	mode os.FileMode
	size int64
	// parts are its layers, by offset once checkCoverage has run.
	parts []partLayer
}

// planComponent plans the restore of descs, a component's layers,
// checking their file parts first: each names a safe path, the parts of a
// file agree on its mode and size, and they cover it exactly, in order,
// with no gap or overlap.
func planComponent(descs []ocispec.Descriptor) (componentPlan, error) {
	var plan componentPlan
	collected := newPartFiles()
	for _, desc := range descs {
		switch desc.MediaType {
		case transfer.LayerMediaType:
			plan.transfers = append(plan.transfers, tarLayer{layerBlob{desc: desc}})
		case transfer.FilePartMediaType:
			part, file, err := parsePart(desc)
			if err != nil {
				return componentPlan{}, err
			}
			if err := collected.add(file, part); err != nil {
				return componentPlan{}, err
			}
		default:
			return componentPlan{}, fmt.Errorf("layer %s is a %s, not a component layer", desc.Digest, desc.MediaType)
		}
	}

	// The parts are transferred once checked, which puts them in order and
	// numbers them.
	if err := collected.checkCoverage(); err != nil {
		return componentPlan{}, err
	}
	for _, file := range collected.files {
		for _, part := range file.parts {
			plan.transfers = append(plan.transfers, part)
		}
	}
	plan.files = collected.files
	return plan, nil
}

// parsePart reads desc's file part annotations (see
// transfer.ParseFilePart): the part, and the file it's part of, without
// its parts.
func parsePart(desc ocispec.Descriptor) (partLayer, partFile, error) {
	annotated, err := transfer.ParseFilePart(desc.Annotations)
	if err != nil {
		return partLayer{}, partFile{}, fmt.Errorf("layer %s: %w", desc.Digest, err)
	}

	part := partLayer{
		layerBlob: layerBlob{desc: desc},
		path:      annotated.Path,
		offset:    annotated.Offset,
	}
	file := partFile{
		path: annotated.Path,
		mode: annotated.Mode,
		size: annotated.FileSize,
	}
	return part, file, nil
}

// partFiles collects the large files a component's parts make up.
type partFiles struct {
	// files are the files, in the order each first appears.
	files []partFile
	// indexByPath is where in files each path's file is.
	indexByPath map[string]int
}

func newPartFiles() *partFiles {
	files := partFiles{
		indexByPath: map[string]int{},
	}
	return &files
}

// add adds part to its file. described is the file as part describes it
// (see parsePart): its first part records the file, and every later part
// must describe it the same way.
func (f *partFiles) add(described partFile, part partLayer) error {
	index, seen := f.indexByPath[described.path]
	if !seen {
		index = len(f.files)
		f.indexByPath[described.path] = index
		f.files = append(f.files, described)
	}

	recorded := &f.files[index]
	if recorded.mode != described.mode || recorded.size != described.size {
		return fmt.Errorf("the parts of %s disagree on its mode or size", described.path)
	}
	recorded.parts = append(recorded.parts, part)
	return nil
}

// checkCoverage sorts and numbers each file's parts, and fails unless
// every file's parts cover it exactly (see partFile.checkCoverage).
func (f *partFiles) checkCoverage() error {
	for index := range f.files {
		if err := f.files[index].checkCoverage(); err != nil {
			return err
		}
	}
	return nil
}

// checkCoverage sorts f's parts by offset, numbering each for its progress
// label, and fails unless they cover it exactly, with no gap or overlap.
func (f *partFile) checkCoverage() error {
	slices.SortFunc(f.parts, func(a, b partLayer) int { return cmp.Compare(a.offset, b.offset) })
	var covered int64
	for index := range f.parts {
		part := &f.parts[index]
		if part.offset != covered {
			return fmt.Errorf("the parts of %s don't cover it: one starts at %d, after %d bytes", f.path, part.offset, covered)
		}
		covered += part.desc.Size
		part.number = index + 1
		part.count = len(f.parts)
	}
	if covered != f.size {
		return fmt.Errorf("the parts of %s cover %d of its %d bytes", f.path, covered, f.size)
	}
	return nil
}

// createFiles creates p's large files under dir, empty and at full size,
// so a tar entry naming one fails rather than overwriting it (see
// transfer.ExtractTarExclusive).
func (p componentPlan) createFiles(dir string) error {
	for _, file := range p.files {
		if err := file.create(dir); err != nil {
			return err
		}
	}
	return nil
}

func (f partFile) create(dir string) error {
	path := filepath.Join(dir, filepath.FromSlash(f.path))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	created, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, f.mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", f.path, err)
	}
	err = created.Truncate(f.size)
	if closeErr := created.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", f.path, err)
	}
	return nil
}
