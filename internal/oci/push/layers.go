package push

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
)

// blobPlan is one blob Push pushes for component, from the file holding
// its bytes, without copying it.
type blobPlan struct {
	component cdx.Component
	// path is the file holding the blob's bytes.
	path string
	// desc is the blob's descriptor: its media type and annotations, and
	// its digest and size, if known; push works them out from the file
	// otherwise.
	desc ocispec.Descriptor
}

// newFilePlan plans file, in component's directory dir, as a blob of
// transfer.FileMediaType, annotated with its purl.
func newFilePlan(component cdx.Component, dir string, file transfer.TarFile) blobPlan {
	plan := blobPlan{
		component: component,
		path:      filepath.Join(dir, filepath.FromSlash(file.Path)),
		desc: ocispec.Descriptor{
			MediaType: transfer.FileMediaType,
			Annotations: map[string]string{
				transfer.AnnotationPurl: component.PackageURL,
			},
		},
	}
	return plan
}

// push pushes the blob straight from its file, hashing it first if its
// digest isn't known, and returns its descriptor. The target checks the
// upload against the digest either way.
func (p blobPlan) push(ctx context.Context, target oras.Target, progress transfer.ProgressFunc) (ocispec.Descriptor, error) {
	file, err := os.Open(p.path)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer file.Close()

	desc := p.desc
	if desc.Digest == "" {
		digester := digest.Canonical.Digester()
		size, err := io.Copy(digester.Hash(), file)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("hash %s: %w", p.path, err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return ocispec.Descriptor{}, err
		}
		desc.Digest = digester.Digest()
		desc.Size = size
	}
	label := transfer.LayerLabel(p.component.PackageURL, desc.Digest.Encoded())
	limited := io.LimitReader(file, desc.Size)
	if err := transfer.PushBlob(ctx, target, desc, limited, label, progress); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", p.path, err)
	}
	return desc, nil
}

// pushLayers pushes the blobs plans plan, up to concurrency at once,
// returning their descriptors in plans' order, whatever order uploads
// finish in: the manifest's layer order is part of its digest.
func pushLayers(ctx context.Context, target oras.Target, plans []blobPlan, concurrency int, progress transfer.ProgressFunc) ([]ocispec.Descriptor, error) {
	pushLayer := func(ctx context.Context, _ int, plan blobPlan) (ocispec.Descriptor, error) {
		desc, err := plan.push(ctx, target, progress)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("%s@%s: %w", plan.component.Name, plan.component.Version, err)
		}
		return desc, nil
	}
	return parallel.Map(ctx, concurrency, plans, pushLayer)
}

// listFiles returns the files build pulled into dir, a component's
// directory, by path. Each must be a regular file: pull restores a
// component file by file, from blobs, which hold nothing else, such as a
// symlink.
func listFiles(dir string) ([]transfer.TarFile, error) {
	files, err := transfer.TarFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	for _, file := range files {
		if !file.Mode.IsRegular() {
			return nil, fmt.Errorf("%s isn't a regular file, which a component's files must be", file.Path)
		}
	}
	slices.SortFunc(files, func(a, b transfer.TarFile) int { return strings.Compare(a.Path, b.Path) })
	return files, nil
}
