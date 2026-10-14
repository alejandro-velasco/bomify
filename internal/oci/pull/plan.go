package pull

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// componentLayer is one of a component's layers, which restore writes into
// its directory: a tar, unpacked, or, with file set, a large file (see
// transfer.FileMediaType), written to its path.
type componentLayer struct {
	desc ocispec.Descriptor
	file *transfer.File
}

// planComponent returns descs, a component's layers, as componentLayers,
// checking their file layers before anything is downloaded: each names a
// safe path, and no two the same one.
func planComponent(descs []ocispec.Descriptor) ([]componentLayer, error) {
	layers := make([]componentLayer, 0, len(descs))
	paths := map[string]bool{}
	for _, desc := range descs {
		layer := componentLayer{desc: desc}
		if desc.MediaType == transfer.FileMediaType {
			file, err := transfer.ParseFile(desc.Annotations)
			if err != nil {
				return nil, fmt.Errorf("layer %s: %w", desc.Digest, err)
			}
			if paths[file.Path] {
				return nil, fmt.Errorf("two layers hold %s", file.Path)
			}
			paths[file.Path] = true
			layer.file = &file
		}
		layers = append(layers, layer)
	}
	return layers, nil
}

// label names the layer, of purl's component, in progress output.
func (l componentLayer) label(purl string) string {
	if l.file != nil {
		return transfer.FileLabel(purl, l.file.Path)
	}
	return transfer.Label(purl, l.desc.Digest.Encoded())
}

// restore writes the layer into dir, verifying it against its digest as it
// streams. No layer may write a file another did: a tar fails on an entry
// naming one that exists (see transfer.ExtractTarExclusive), as does a
// file.
func (l componentLayer) restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error {
	if l.file != nil {
		return l.restoreFile(ctx, target, dir, label, progress)
	}
	unpack := func(r io.Reader) error {
		if err := transfer.ExtractTarExclusive(tar.NewReader(r), dir); err != nil {
			return fmt.Errorf("unpack: %w", err)
		}
		return nil
	}
	return l.fetch(ctx, target, label, progress, unpack)
}

// restoreFile writes the file under dir through an os.Root of dir, so not
// even a symlink a tar made can lead it outside.
func (l componentLayer) restoreFile(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	path := filepath.FromSlash(l.file.Path)
	if err := root.MkdirAll(filepath.Dir(path), transfer.DirPerm); err != nil {
		return fmt.Errorf("create %s: %w", l.file.Path, err)
	}
	file, err := root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, l.file.Mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", l.file.Path, err)
	}
	defer file.Close()

	write := func(r io.Reader) error {
		_, err := io.Copy(file, r)
		return err
	}
	if err := l.fetch(ctx, target, label, progress, write); err != nil {
		return err
	}
	return file.Close()
}

// fetch streams the layer's content to consume, with its progress bar, and
// fails unless all of it matches its digest, including anything consume
// leaves unread, such as a tar's padding after its end-of-archive marker.
func (l componentLayer) fetch(ctx context.Context, target oras.ReadOnlyTarget, label string, progress transfer.ProgressFunc, consume func(io.Reader) error) error {
	rc, err := target.Fetch(ctx, l.desc)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", l.desc.Digest, err)
	}
	defer rc.Close()

	pw := progress(label, l.desc.Size)
	defer pw.Close()

	verified := content.NewVerifyReader(rc, l.desc)
	reader := io.TeeReader(verified, pw)
	if err := consume(reader); err != nil {
		return fmt.Errorf("%s: %w", l.desc.Digest, err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("download %s: %w", l.desc.Digest, err)
	}
	if err := verified.Verify(); err != nil {
		return fmt.Errorf("verify %s: %w", l.desc.Digest, err)
	}
	return nil
}
