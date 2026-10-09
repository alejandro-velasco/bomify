package push

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
)

// layerPlan is one layer Push pushes for a component: a tar of some of
// its files, or one part of one of its large files (see
// transfer.FilePartMediaType).
type layerPlan struct {
	component cdx.Component
	// dir is the component's directory, "<baseDir>/layers/<purl-hash>/".
	dir string
	// tarFiles are the files a tar layer holds; unused for a part.
	tarFiles []transfer.TarFile
	// part, if set, makes this a file part layer.
	part *filePart
}

// filePart is one part of a large file: length bytes from its Offset.
type filePart struct {
	// FilePart is what the part's annotations say.
	transfer.FilePart
	length int64
	// number is which of the file's count parts this is, from 1.
	number, count int
}

// planLayers plans each of components' layers, in the order they go in
// the manifest (see planComponentLayers).
func planLayers(baseDir string, components []cdx.Component) ([]layerPlan, error) {
	var plans []layerPlan
	for _, component := range components {
		componentPlans, err := planComponentLayers(baseDir, component)
		if err != nil {
			return nil, fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
		}
		plans = append(plans, componentPlans...)
	}
	return plans, nil
}

// pushLayers pushes the layers plans plan, up to concurrency at once,
// returning their descriptors in plans' order, whatever order uploads
// finish in: the manifest's layer order is part of its digest.
func pushLayers(ctx context.Context, target oras.Target, plans []layerPlan, concurrency int, progress transfer.ProgressFunc) ([]ocispec.Descriptor, error) {
	pushLayer := func(ctx context.Context, _ int, plan layerPlan) (ocispec.Descriptor, error) {
		desc, err := plan.push(ctx, target, progress)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("%s@%s: %w", plan.component.Name, plan.component.Version, err)
		}
		return desc, nil
	}
	return parallel.Map(ctx, concurrency, plans, pushLayer)
}

// pushedLayers reports each layer of plans, pushed as the matching one of
// descs.
func pushedLayers(plans []layerPlan, descs []ocispec.Descriptor) []PushedLayer {
	layers := make([]PushedLayer, 0, len(plans))
	for index, plan := range plans {
		layer := PushedLayer{
			Purl: plan.component.PackageURL,
			Hash: descs[index].Digest.Encoded(),
		}
		layers = append(layers, layer)
	}
	return layers
}

// planComponentLayers plans component's layers, in the order they go in
// the manifest: its files under transfer.LargeFileSize in tar layers of at
// most transfer.MaxLayerSize, then each larger file, by path, in parts of
// at most transfer.MaxLayerSize. A component with no files gets one empty
// tar layer, so pull still restores its directory.
func planComponentLayers(baseDir string, component cdx.Component) ([]layerPlan, error) {
	dir := layout.ComponentLayer(baseDir, component.PackageURL)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("no local layer at %s (run `bomify build` first)", dir)
	}
	files, err := transfer.TarFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}

	var smallFiles []transfer.TarFile
	var parts []layerPlan
	for _, file := range files {
		// Only a regular file's content can be streamed in parts; anything
		// else, such as a symlink, goes in a tar whatever its size.
		if file.Size >= transfer.LargeFileSize && file.Mode.IsRegular() {
			parts = append(parts, planFileParts(component, dir, file)...)
		} else {
			smallFiles = append(smallFiles, file)
		}
	}
	tars := planTars(component, dir, smallFiles)
	// A component with no files at all still needs a layer, or pull would
	// never create its directory.
	if len(tars) == 0 && len(parts) == 0 {
		tars = append(tars, tarPlan(component, dir, nil))
	}
	return append(tars, parts...), nil
}

// planTars plans files, small files in component's directory dir, as tar
// layers of at most transfer.MaxLayerSize, in order, starting the next
// tar whenever a file won't fit in this one.
func planTars(component cdx.Component, dir string, files []transfer.TarFile) []layerPlan {
	var plans []layerPlan
	var tarFiles []transfer.TarFile
	var tarSize int64
	for _, file := range files {
		entrySize := transfer.TarSize(file.Size)
		// The file would take this tar past transfer.MaxLayerSize: close it
		// and start the next with the file. A tar's first file always goes
		// in, so a tar is never empty.
		if len(tarFiles) > 0 && tarSize+entrySize > transfer.MaxLayerSize {
			plans = append(plans, tarPlan(component, dir, tarFiles))
			tarFiles, tarSize = nil, 0
		}
		tarFiles = append(tarFiles, file)
		tarSize += entrySize
	}
	// Close the last tar, holding whatever files are left over: none only
	// if there were no files at all.
	if len(tarFiles) > 0 {
		plans = append(plans, tarPlan(component, dir, tarFiles))
	}
	return plans
}

// tarPlan plans one tar layer of files, in component's directory dir.
func tarPlan(component cdx.Component, dir string, files []transfer.TarFile) layerPlan {
	plan := layerPlan{
		component: component,
		dir:       dir,
		tarFiles:  files,
	}
	return plan
}

// planFileParts plans file, a large file in component's directory dir,
// as parts of at most transfer.MaxLayerSize, by offset.
func planFileParts(component cdx.Component, dir string, file transfer.TarFile) []layerPlan {
	count := int((file.Size + transfer.MaxLayerSize - 1) / transfer.MaxLayerSize)
	plans := make([]layerPlan, 0, count)
	for index := range count {
		offset := int64(index) * transfer.MaxLayerSize
		part := filePart{
			FilePart: transfer.FilePart{
				Path:     file.Path,
				Mode:     file.Mode.Perm(),
				FileSize: file.Size,
				Offset:   offset,
			},
			length: min(transfer.MaxLayerSize, file.Size-offset),
			number: index + 1,
			count:  count,
		}
		plan := layerPlan{
			component: component,
			dir:       dir,
			part:      &part,
		}
		plans = append(plans, plan)
	}
	return plans
}

// push pushes the layer p plans, returning its descriptor.
func (p layerPlan) push(ctx context.Context, target oras.Target, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	if p.part != nil {
		return p.pushPart(ctx, target, progress)
	}
	return p.pushTar(ctx, target, progress)
}

// pushTar archives p's files (see transfer.WriteTarFiles) into a temp
// file, to learn its digest, and pushes it.
func (p layerPlan) pushTar(ctx context.Context, target oras.Target, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	tmp, err := os.CreateTemp("", "bomify-push-layer-*.tar")
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	hasher := sha256.New()
	if err := transfer.WriteTarFiles(p.dir, p.tarFiles, io.MultiWriter(tmp, hasher)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("archive %s: %w", p.dir, err)
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	desc := ocispec.Descriptor{
		MediaType: transfer.LayerMediaType,
		Digest:    digest.NewDigestFromEncoded(digest.SHA256, hash),
		Size:      size,
		Annotations: map[string]string{
			ocispec.AnnotationTitle: hash + ".tar",
			transfer.AnnotationPurl: p.component.PackageURL,
		},
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return ocispec.Descriptor{}, err
	}
	if err := transfer.PushBlob(ctx, target, desc, tmp, transfer.Label(p.component.PackageURL, hash), progress); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push layer: %w", err)
	}
	return desc, nil
}

// pushPart pushes p's part of its file straight from the file: once to
// learn its digest, then again to upload it, so a large file is never
// copied.
func (p layerPlan) pushPart(ctx context.Context, target oras.Target, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	part := p.part
	file, err := os.Open(filepath.Join(p.dir, filepath.FromSlash(part.Path)))
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file, part.Offset, part.length)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("hash %s: %w", part.Path, err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	desc := ocispec.Descriptor{
		MediaType:   transfer.FilePartMediaType,
		Digest:      digest.NewDigestFromEncoded(digest.SHA256, hash),
		Size:        part.length,
		Annotations: part.Annotations(p.component.PackageURL),
	}
	section := io.NewSectionReader(file, part.Offset, part.length)
	label := transfer.PartLabel(p.component.PackageURL, part.Path, part.number, part.count)
	if err := transfer.PushBlob(ctx, target, desc, section, label, progress); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", part.Path, err)
	}
	return desc, nil
}
