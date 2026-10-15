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

// layerPlan is one layer Push pushes for a component, its owner, from the
// component's directory: a tarPlan or a filePlan. push pushes it,
// returning its descriptor.
type layerPlan interface {
	owner() cdx.Component
	directory() string
	push(ctx context.Context, target oras.Target, progress transfer.ProgressFunc) (ocispec.Descriptor, error)
}

// componentDir is the component a layerPlan is of, and its directory.
type componentDir struct {
	component cdx.Component
	// dir is the component's directory, "<baseDir>/layers/<purl-hash>/".
	dir string
}

func (c componentDir) owner() cdx.Component {
	return c.component
}

func (c componentDir) directory() string {
	return c.dir
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
			owner := plan.owner()
			return ocispec.Descriptor{}, fmt.Errorf("%s@%s: %w", owner.Name, owner.Version, err)
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
			Purl: plan.owner().PackageURL,
			Hash: descs[index].Digest.Encoded(),
		}
		layers = append(layers, layer)
	}
	return layers
}

// planComponentLayers plans component's layers, in the order they go in
// the manifest: its files under transfer.LargeFileSize in tar layers of at
// most transfer.MaxTarSize, then each larger file, by path, as a layer of
// its own. A component with no files gets one empty tar layer, so pull
// still restores its directory.
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
	var largeFiles []layerPlan
	for _, file := range files {
		// Only a regular file's content can be a layer of its own; anything
		// else, such as a symlink, goes in a tar whatever its size.
		if file.Size >= transfer.LargeFileSize && file.Mode.IsRegular() {
			largeFiles = append(largeFiles, newFilePlan(component, dir, file))
		} else {
			smallFiles = append(smallFiles, file)
		}
	}
	tars := planTars(component, dir, smallFiles)
	// A component with no files at all still needs a layer, or pull would
	// never create its directory.
	if len(tars) == 0 && len(largeFiles) == 0 {
		tars = append(tars, newTarPlan(component, dir, nil))
	}
	return append(tars, largeFiles...), nil
}

// planTars plans files, small files in component's directory dir, as tar
// layers of at most transfer.MaxTarSize, in order, starting the next
// tar whenever a file won't fit in this one.
func planTars(component cdx.Component, dir string, files []transfer.TarFile) []layerPlan {
	var plans []layerPlan
	var tarFiles []transfer.TarFile
	var tarSize int64
	for _, file := range files {
		entrySize := transfer.TarSize(file.Size)
		// The file would take this tar past transfer.MaxTarSize: close it
		// and start the next with the file. A tar's first file always goes
		// in, so a tar is never empty.
		if len(tarFiles) > 0 && tarSize+entrySize > transfer.MaxTarSize {
			plans = append(plans, newTarPlan(component, dir, tarFiles))
			tarFiles, tarSize = nil, 0
		}
		tarFiles = append(tarFiles, file)
		tarSize += entrySize
	}
	// Close the last tar, holding whatever files are left over: none only
	// if there were no files at all.
	if len(tarFiles) > 0 {
		plans = append(plans, newTarPlan(component, dir, tarFiles))
	}
	return plans
}

// tarPlan is a tar layer of some of a component's files (see
// transfer.LayerMediaType).
type tarPlan struct {
	componentDir
	files []transfer.TarFile
}

// newTarPlan plans one tar layer of files, in component's directory dir.
func newTarPlan(component cdx.Component, dir string, files []transfer.TarFile) tarPlan {
	plan := tarPlan{
		componentDir: componentDir{
			component: component,
			dir:       dir,
		},
		files: files,
	}
	return plan
}

// push archives p's files (see transfer.WriteTarFiles) into a temp file,
// to learn its digest, and pushes it.
func (p tarPlan) push(ctx context.Context, target oras.Target, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	tmp, err := os.CreateTemp("", "bomify-push-layer-*.tar")
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	hasher := sha256.New()
	if err := transfer.WriteTarFiles(p.dir, p.files, io.MultiWriter(tmp, hasher)); err != nil {
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
	if err := transfer.PushBlob(ctx, target, desc, tmp, transfer.LayerLabel(p.component.PackageURL, hash), progress); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push layer: %w", err)
	}
	return desc, nil
}

// filePlan is one of a component's large files, as a layer of its own (see
// transfer.FileMediaType).
type filePlan struct {
	componentDir
	file transfer.File
}

// newFilePlan plans file, a large file in component's directory dir, as a
// layer of its own.
func newFilePlan(component cdx.Component, dir string, file transfer.TarFile) filePlan {
	plan := filePlan{
		componentDir: componentDir{
			component: component,
			dir:       dir,
		},
		file: transfer.File{
			Path: file.Path,
			Mode: file.Mode.Perm(),
		},
	}
	return plan
}

// push pushes p's file straight from the file: once to learn its digest,
// then again to upload it, so a large file is never copied.
func (p filePlan) push(ctx context.Context, target oras.Target, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	file, err := os.Open(filepath.Join(p.dir, filepath.FromSlash(p.file.Path)))
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("hash %s: %w", p.file.Path, err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	desc := ocispec.Descriptor{
		MediaType:   transfer.FileMediaType,
		Digest:      digest.NewDigestFromEncoded(digest.SHA256, hash),
		Size:        size,
		Annotations: p.file.Annotations(p.component.PackageURL),
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ocispec.Descriptor{}, err
	}
	label := transfer.LayerLabel(p.component.PackageURL, hash)
	if err := transfer.PushBlob(ctx, target, desc, io.LimitReader(file, size), label, progress); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", p.file.Path, err)
	}
	return desc, nil
}
