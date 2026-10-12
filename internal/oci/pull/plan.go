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

// layerTransfer is one of a component's layers, which restore writes into
// dir, verifying it against its digest as it streams.
type layerTransfer interface {
	// label names the layer, of purl's component, in progress output.
	label(purl string) string
	restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error
}

// layerBlob is a layer's blob: what tarLayer and fileLayer share.
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

func (t tarLayer) label(purl string) string {
	return transfer.Label(purl, t.desc.Digest.Encoded())
}

// fileLayer is a large file's layer (see transfer.FileMediaType), written
// to its path in the component's directory.
type fileLayer struct {
	layerBlob
	transfer.File
}

func (f fileLayer) label(purl string) string {
	return transfer.FileLabel(purl, f.Path)
}

// restore writes the file under dir, failing if it exists, since no layer
// may write a file another did. It writes through an os.Root of dir, so
// not even a symlink a tar made can lead it outside.
func (f fileLayer) restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	path := filepath.FromSlash(f.Path)
	if err := root.MkdirAll(filepath.Dir(path), transfer.DirPerm); err != nil {
		return fmt.Errorf("create %s: %w", f.Path, err)
	}
	file, err := root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, f.Mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", f.Path, err)
	}
	defer file.Close()

	write := func(r io.Reader) error {
		_, err := io.Copy(file, r)
		return err
	}
	if err := f.fetch(ctx, target, label, progress, write); err != nil {
		return err
	}
	return file.Close()
}

// planComponent plans the restore of descs, a component's layers, in
// order, checking their file layers first: each names a safe path, and
// no two the same one.
func planComponent(descs []ocispec.Descriptor) ([]layerTransfer, error) {
	transfers := make([]layerTransfer, 0, len(descs))
	paths := map[string]bool{}
	for _, desc := range descs {
		switch desc.MediaType {
		case transfer.LayerMediaType:
			transfers = append(transfers, tarLayer{layerBlob{desc: desc}})
		case transfer.FileMediaType:
			file, err := transfer.ParseFile(desc.Annotations)
			if err != nil {
				return nil, fmt.Errorf("layer %s: %w", desc.Digest, err)
			}
			if paths[file.Path] {
				return nil, fmt.Errorf("two layers hold %s", file.Path)
			}
			paths[file.Path] = true
			transfers = append(transfers, fileLayer{layerBlob: layerBlob{desc: desc}, File: file})
		default:
			return nil, fmt.Errorf("layer %s is a %s, not a component layer", desc.Digest, desc.MediaType)
		}
	}
	return transfers, nil
}
