// Package save lets a bomify package move between machines as a single
// tarball, with no registry involved: Save packages one or more tags into
// an OCI image-layout directory and archives that directory into a
// tarball; Load does the reverse, restoring every tag the tarball
// contains into a data directory exactly as `bomify pull` would have for
// each. Both are thin wrappers around internal/oci/push and
// internal/oci/pull: an OCI image-layout directory satisfies the same
// oras.Target/oras.ReadOnlyTarget interfaces those packages already push
// to and pull from over a network, so no new packing/unpacking logic is
// needed here.
package save

import (
	"context"
	"fmt"
	"io"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// Save resolves each of tags in baseDir's repositories.json and packages
// them all into a single OCI image-layout tarball written to w — a
// self-contained archive Load can restore from later, on this machine or
// any other, with no registry involved. Shared components (the same purl
// pulled by more than one of the given tags) are stored once. Layers
// upload concurrently within each tag, bounded by opts.Concurrency. A
// non-nil opts.Sign signs each tag's package as push.Push would (see
// transfer.Signer), its signature travelling inside the tarball as an
// OCI referrer.
func Save(ctx context.Context, baseDir string, tags []string, w io.Writer, opts transfer.Options) error {
	if len(tags) == 0 {
		return fmt.Errorf("no tags to save")
	}

	archive, err := NewArchive()
	if err != nil {
		return err
	}
	defer archive.Close()

	for _, tag := range tags {
		sbomHash, err := build.ResolveTag(baseDir, tag)
		if err != nil {
			return err
		}
		if _, err := push.Push(ctx, archive.Store, tag, baseDir, sbomHash, opts); err != nil {
			return fmt.Errorf("package %s: %w", tag, err)
		}
	}

	return archive.WriteTar(w)
}

// Loaded is one tag Load restored.
type Loaded struct {
	// Tag is the tag as the archive recorded it.
	Tag string
	// ManifestDigest is the digest of the package manifest it restored
	// for Tag, as "sha256:...".
	ManifestDigest string
	// ReportsSkipped is why Tag's vulnerability reports weren't restored
	// (see pull.Result.ReportsSkipped), or nil.
	ReportsSkipped error
}

// Load extracts r — an OCI image-layout tarball Save produced — and
// restores every tag it contains into baseDir exactly as `bomify pull`
// would have for each, recording each in repositories.json. Returns the
// tags it found and restored. opts.Verify and opts.Scan are applied to
// each tag exactly as pull.Pull applies them, and a tag either fails
// isn't recorded.
func Load(ctx context.Context, baseDir string, r io.Reader, opts transfer.Options) ([]Loaded, error) {
	archive, err := OpenArchive(r)
	if err != nil {
		return nil, err
	}
	defer archive.Close()

	tags, err := archive.Tags(ctx)
	if err != nil {
		return nil, err
	}

	loaded := make([]Loaded, 0, len(tags))
	for _, tag := range tags {
		result, err := pull.Pull(ctx, archive.Store, tag, baseDir, opts)
		if err != nil {
			return nil, fmt.Errorf("restore %s: %w", tag, err)
		}
		if err := build.UpdateRepositories(baseDir, []string{tag}, result.SBOMHash); err != nil {
			return nil, fmt.Errorf("record %s: %w", tag, err)
		}
		loaded = append(loaded, Loaded{Tag: tag, ManifestDigest: result.ManifestDigest, ReportsSkipped: result.ReportsSkipped})
	}

	return loaded, nil
}
