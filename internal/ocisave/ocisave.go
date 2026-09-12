// Package ocisave lets a bomify package move between machines as a single
// tarball, with no registry involved: Save packages one or more tags into
// an OCI image-layout directory (the same layout internal/ocipush already
// knows how to write to, and bomify-plugin-oci itself uses) and archives
// that directory into a tarball; Load does the reverse, restoring every
// tag the tarball contains into a data directory exactly as `bomify pull`
// would have for each. Both are thin wrappers around internal/ocipush and
// internal/ocipull: an OCI image-layout directory (content/oci.Store)
// satisfies the same oras.Target/oras.ReadOnlyTarget interfaces those
// packages already push to and pull from over a network, so pointing them
// at a local directory instead needs no new packing/unpacking logic here.
package ocisave

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"

	"oras.land/oras-go/v2/content/oci"

	"bomify/internal/build"
	"bomify/internal/ocipull"
	"bomify/internal/ocipush"
	"bomify/internal/ocitransfer"
)

// Save resolves each of tags in baseDir's repositories.json and packages
// them all into a single OCI image-layout tarball written to w — a
// self-contained archive Load can restore from later, on this machine or
// any other, with no registry involved. Shared components (the same purl
// pulled by more than one of the given tags) are stored once. Layers
// upload concurrently within each tag, bounded by concurrency.
func Save(ctx context.Context, baseDir string, tags []string, w io.Writer, concurrency int, progress ocitransfer.ProgressFunc) error {
	if len(tags) == 0 {
		return fmt.Errorf("no tags to save")
	}

	stageDir, err := os.MkdirTemp("", "bomify-save-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)

	store, err := oci.New(stageDir)
	if err != nil {
		return fmt.Errorf("create oci layout store: %w", err)
	}

	for _, tag := range tags {
		sbomHash, err := build.ResolveTag(baseDir, tag)
		if err != nil {
			return err
		}
		if _, err := ocipush.Push(ctx, store, tag, baseDir, sbomHash, concurrency, progress); err != nil {
			return fmt.Errorf("package %s: %w", tag, err)
		}
	}

	if err := ocitransfer.WriteTar(stageDir, w); err != nil {
		return fmt.Errorf("archive: %w", err)
	}

	return nil
}

// Load extracts r — an OCI image-layout tarball Save produced — and
// restores every tag it contains into baseDir exactly as `bomify pull`
// would have for each, recording each in repositories.json. Returns the
// tags it found and restored.
func Load(ctx context.Context, baseDir string, r io.Reader, concurrency int, progress ocitransfer.ProgressFunc) ([]string, error) {
	stageDir, err := os.MkdirTemp("", "bomify-load-*")
	if err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)

	if err := ocitransfer.ExtractTar(tar.NewReader(r), stageDir); err != nil {
		return nil, fmt.Errorf("extract archive: %w", err)
	}

	store, err := oci.New(stageDir)
	if err != nil {
		return nil, fmt.Errorf("open oci layout store: %w", err)
	}

	tags, err := listTags(ctx, store)
	if err != nil {
		return nil, err
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("archive contains no tags")
	}

	for _, tag := range tags {
		result, err := ocipull.Pull(ctx, store, tag, baseDir, concurrency, progress)
		if err != nil {
			return nil, fmt.Errorf("restore %s: %w", tag, err)
		}
		if err := build.UpdateRepositories(baseDir, []string{tag}, result.SBOMHash); err != nil {
			return nil, fmt.Errorf("record %s: %w", tag, err)
		}
	}

	return tags, nil
}

func listTags(ctx context.Context, store *oci.Store) ([]string, error) {
	var tags []string
	err := store.Tags(ctx, "", func(page []string) error {
		tags = append(tags, page...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list tags: %w", err)
	}
	return tags, nil
}
