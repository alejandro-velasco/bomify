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

// componentLayer is one of a component's layers, a tarLayer or a
// fileLayer, which restore writes into the component's directory, dir,
// verifying it against its digest as it streams. No layer may write a file
// another did.
type componentLayer interface {
	descriptor() ocispec.Descriptor
	restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error
}

// newComponentLayers returns descs, a component's layers, as componentLayers,
// checking them before anything is downloaded: each is a tar or a large
// file, and each file names a safe path, no two the same one.
func newComponentLayers(descs []ocispec.Descriptor) ([]componentLayer, error) {
	layers := make([]componentLayer, 0, len(descs))
	paths := map[string]bool{}
	for _, desc := range descs {
		switch desc.MediaType {
		case transfer.LayerMediaType:
			layer := tarLayer{
				desc: desc,
			}
			layers = append(layers, layer)
		case transfer.FileMediaType:
			file, err := transfer.ParseFile(desc.Annotations)
			if err != nil {
				return nil, fmt.Errorf("layer %s: %w", desc.Digest, err)
			}
			if paths[file.Path] {
				return nil, fmt.Errorf("two layers hold %s", file.Path)
			}
			paths[file.Path] = true
			layer := fileLayer{
				desc: desc,
				file: file,
			}
			layers = append(layers, layer)
		default:
			return nil, fmt.Errorf("layer %s: media type %q isn't a component layer's", desc.Digest, desc.MediaType)
		}
	}
	return layers, nil
}

// tarLayer is a tar of a component's files (see transfer.LayerMediaType),
// unpacked into its directory.
type tarLayer struct {
	desc ocispec.Descriptor
}

func (l tarLayer) descriptor() ocispec.Descriptor {
	return l.desc
}

// restore unpacks the tar into dir, failing on an entry naming a file that
// exists (see transfer.ExtractTarExclusive).
func (l tarLayer) restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error {
	unpack := func(r io.Reader) error {
		if err := transfer.ExtractTarExclusive(tar.NewReader(r), dir); err != nil {
			return fmt.Errorf("unpack: %w", err)
		}
		return nil
	}
	return streamLayer(ctx, target, l.desc, label, progress, unpack)
}

// fileLayer is one of a component's large files (see
// transfer.FileMediaType), written to its path.
type fileLayer struct {
	desc ocispec.Descriptor
	file transfer.File
}

func (l fileLayer) descriptor() ocispec.Descriptor {
	return l.desc
}

// restore writes the file under dir through an os.Root of dir, so not even
// a symlink a tar made can lead it outside, failing if the file exists.
func (l fileLayer) restore(ctx context.Context, target oras.ReadOnlyTarget, dir, label string, progress transfer.ProgressFunc) error {
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
	if err := streamLayer(ctx, target, l.desc, label, progress, write); err != nil {
		return err
	}
	return file.Close()
}

// streamLayer streams desc's content to consume, with its progress bar, and
// fails unless all of it matches its digest, including anything consume
// leaves unread, such as a tar's padding after its end-of-archive marker.
func streamLayer(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor, label string, progress transfer.ProgressFunc, consume func(io.Reader) error) error {
	rc, err := target.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", desc.Digest, err)
	}
	defer rc.Close()

	pw := progress(label, desc.Size)
	defer pw.Close()

	verified := content.NewVerifyReader(rc, desc)
	reader := io.TeeReader(verified, pw)
	if err := consume(reader); err != nil {
		return fmt.Errorf("%s: %w", desc.Digest, err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("download %s: %w", desc.Digest, err)
	}
	if err := verified.Verify(); err != nil {
		return fmt.Errorf("verify %s: %w", desc.Digest, err)
	}
	return nil
}
