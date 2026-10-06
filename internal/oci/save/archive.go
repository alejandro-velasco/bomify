package save

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// Archive is a save tarball staged as an OCI image-layout directory,
// which Store reads and writes like any other target. Close removes it.
type Archive struct {
	Store *oci.Store
	dir   string
}

// NewArchive stages an empty archive, for packages to be pushed into
// Store and the result archived with WriteTar.
func NewArchive() (*Archive, error) {
	return OpenArchive(nil)
}

// OpenArchive stages r, a tarball Save wrote, or an empty archive if r is
// nil (see NewArchive).
func OpenArchive(r io.Reader) (*Archive, error) {
	dir, err := os.MkdirTemp("", "bomify-archive-*")
	if err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	if r != nil {
		if err := transfer.ExtractTar(tar.NewReader(r), dir); err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("extract archive: %w", err)
		}
	}
	store, err := oci.New(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("open oci layout store: %w", err)
	}
	archive := &Archive{
		Store: store,
		dir:   dir,
	}
	return archive, nil
}

// Tags lists the archive's tags, failing if it has none.
func (a *Archive) Tags(ctx context.Context) ([]string, error) {
	var tags []string
	err := a.Store.Tags(ctx, "", func(page []string) error {
		tags = append(tags, page...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}
	if len(tags) == 0 {
		return nil, errors.New("archive contains no tags")
	}
	return tags, nil
}

// WriteTar writes the archive to w as a tarball.
func (a *Archive) WriteTar(w io.Writer) error {
	if err := transfer.WriteTar(a.dir, w); err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	return nil
}

// Close removes the staging directory.
func (a *Archive) Close() error {
	return os.RemoveAll(a.dir)
}
