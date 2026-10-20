package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	modelspec "github.com/modelpack/model-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// componentPlan is how Push packages one component in the package's
// index: in bomify's own format (bomifyComponent), in its kind's registry
// format, as its plugin packed it (packedComponent), or as a ModelPack
// model (modelPackComponent).
type componentPlan interface {
	// layers are the blobs to push before the component's manifest,
	// alongside every other component's.
	layers() []blobPlan
	// pushManifest pushes the component's manifest, once its layers are
	// pushed as descs.
	pushManifest(ctx context.Context, target oras.Target, descs []ocispec.Descriptor, opts transfer.Options) (componentManifest, error)
}

// componentManifest is a component's pushed manifest, and what the
// package's SBOM manifest needs to restore it: its files map entry, and
// the blobs holding the files its format has no place for, which the SBOM
// manifest carries as layers.
type componentManifest struct {
	desc   ocispec.Descriptor
	files  transfer.ComponentFiles
	extras []ocispec.Descriptor
}

// planComponents plans each of components, up to opts.Concurrency at once
// (see planComponent).
func planComponents(ctx context.Context, baseDir string, components []cdx.Component, opts transfer.Options) ([]componentPlan, error) {
	plan := func(ctx context.Context, _ int, component cdx.Component) (componentPlan, error) {
		plan, err := planComponent(ctx, baseDir, component, opts)
		if err != nil {
			return nil, fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
		}
		return plan, nil
	}
	return parallel.Map(ctx, opts.Concurrency, components, plan)
}

// planComponent plans component, which build pulled under baseDir: as its
// plugin packs it, if opts.Pack packs it; else a model with files as
// ModelPack; else in bomify's own format.
func planComponent(ctx context.Context, baseDir string, component cdx.Component, opts transfer.Options) (componentPlan, error) {
	dir := layout.ComponentLayer(baseDir, component.PackageURL)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("no local layer at %s (run `bomify build` first)", dir)
	}

	if opts.Pack != nil {
		packed, err := opts.Pack(ctx, component, dir)
		if err != nil {
			return nil, fmt.Errorf("pack: %w", err)
		}
		if packed.Manifest != nil {
			return newPackedComponent(component, dir, *packed)
		}
		if len(packed.Blobs) > 0 {
			return nil, fmt.Errorf("pack: %d blobs, but no manifest", len(packed.Blobs))
		}
	}

	if component.Type == cdx.ComponentTypeMachineLearningModel {
		model, ok, err := newModelPackComponent(component, dir)
		if err != nil || ok {
			return model, err
		}
	}

	return newBomifyComponent(component, dir)
}

// fileBlobs are files of a component, each pushed as a blob of its own and
// restored from it: all of a component in bomify's own format or a
// ModelPack model, or the extras of a packed one. It's no componentPlan:
// extras have no manifest of their own.
type fileBlobs struct {
	component cdx.Component
	files     []plannedFile
}

// plannedFile is one of a component's files, and the plan of its blob.
type plannedFile struct {
	file transfer.TarFile
	plan blobPlan
}

// newFileBlobs plans files, of component's directory dir, as blobs of
// transfer.FileMediaType annotated with its purl, then has describe, if
// it's non-nil, set each one's media type and annotations as its format
// has them.
func newFileBlobs(component cdx.Component, dir string, files []transfer.TarFile, describe func(file transfer.TarFile, desc *ocispec.Descriptor)) fileBlobs {
	blobs := fileBlobs{component: component}
	for _, file := range files {
		plan := newFilePlan(component, dir, file)
		if describe != nil {
			describe(file, &plan.desc)
		}
		planned := plannedFile{
			file: file,
			plan: plan,
		}
		blobs.files = append(blobs.files, planned)
	}
	return blobs
}

func (b fileBlobs) layers() []blobPlan {
	plans := make([]blobPlan, 0, len(b.files))
	for _, planned := range b.files {
		plans = append(plans, planned.plan)
	}
	return plans
}

// mapFiles returns b's files as the files map has them, by path, their
// blobs pushed as descs. descs are in layers' order, as pushLayers returns
// them, whatever order uploads finish in, so each is its file's.
func (b fileBlobs) mapFiles(descs []ocispec.Descriptor) []transfer.FileBlob {
	files := make([]transfer.FileBlob, 0, len(b.files))
	for index, planned := range b.files {
		file := transfer.NewFileBlob(planned.file.Path, planned.file.Mode, descs[index])
		files = append(files, file)
	}
	sortFiles(files)
	return files
}

// bomifyComponent is a component in bomify's own format (see
// transfer.ComponentArtifactType): each of its files a layer of its own.
type bomifyComponent struct {
	fileBlobs
}

// newBomifyComponent plans component, whose files build pulled into dir,
// in bomify's own format (see titleFile).
func newBomifyComponent(component cdx.Component, dir string) (bomifyComponent, error) {
	files, err := listFiles(dir)
	if err != nil {
		return bomifyComponent{}, err
	}
	blobs := newFileBlobs(component, dir, files, titleFile)
	c := bomifyComponent{
		fileBlobs: blobs,
	}
	return c, nil
}

// titleFile titles desc, file's layer in bomify's own format, with file's
// path, so `oras pull` writes the component out as it is.
func titleFile(file transfer.TarFile, desc *ocispec.Descriptor) {
	desc.Annotations[ocispec.AnnotationTitle] = file.Path
}

// pushManifest pushes the component's manifest, with an empty config, and
// for a component with no files, the empty descriptor as its one layer,
// as OCI suggests for an artifact without any.
func (c bomifyComponent) pushManifest(ctx context.Context, target oras.Target, descs []ocispec.Descriptor, _ transfer.Options) (componentManifest, error) {
	config, err := pushEmptyConfig(ctx, target)
	if err != nil {
		return componentManifest{}, err
	}
	layers := descs
	if len(layers) == 0 {
		layers = []ocispec.Descriptor{config}
	}
	desc, err := pushManifest(ctx, target, transfer.ComponentArtifactType, config, layers, nil)
	if err != nil {
		return componentManifest{}, err
	}
	mapped := c.mapFiles(descs)
	files := transfer.ComponentFiles{
		Purl:  c.component.PackageURL,
		Files: mapped,
	}
	manifest := componentManifest{
		desc:  desc,
		files: files,
	}
	return manifest, nil
}

// modelWeightSize is the size from which a model's file is a ModelPack
// weight, rather than weight configuration. A variable so tests can make
// it small.
var modelWeightSize int64 = 64 << 20

// modelPackComponent is a model, as a ModelPack artifact: each of its files
// a raw layer of its own.
type modelPackComponent struct {
	fileBlobs
}

// newModelPackComponent plans component, a model whose files build pulled
// into dir, as a ModelPack artifact (see describeModelFile), or reports
// false if it has no files, leaving it to bomify's own format.
func newModelPackComponent(component cdx.Component, dir string) (modelPackComponent, bool, error) {
	files, err := listFiles(dir)
	if err != nil {
		return modelPackComponent{}, false, err
	}
	if len(files) == 0 {
		return modelPackComponent{}, false, nil
	}
	blobs := newFileBlobs(component, dir, files, describeModelFile)
	model := modelPackComponent{
		fileBlobs: blobs,
	}
	return model, true, nil
}

// describeModelFile describes desc, file's layer of a ModelPack model: a
// weight if it's modelWeightSize or more, and weight configuration
// otherwise, both marked untested, since nothing checks what they hold,
// and titled with its path, so `oras pull` writes the model out as it is.
func describeModelFile(file transfer.TarFile, desc *ocispec.Descriptor) {
	desc.MediaType = modelspec.MediaTypeModelWeightConfigRaw
	if file.Size >= modelWeightSize {
		desc.MediaType = modelspec.MediaTypeModelWeightRaw
	}
	desc.Annotations = map[string]string{
		ocispec.AnnotationTitle:               file.Path,
		modelspec.AnnotationFilepath:          file.Path,
		modelspec.AnnotationMediaTypeUntested: "true",
	}
}

// pushManifest pushes the model's ModelPack config, naming its layers,
// descs, as its uncompressed content, and then its manifest.
func (c modelPackComponent) pushManifest(ctx context.Context, target oras.Target, descs []ocispec.Descriptor, opts transfer.Options) (componentManifest, error) {
	diffIDs := make([]digest.Digest, 0, len(descs))
	for _, desc := range descs {
		diffIDs = append(diffIDs, desc.Digest)
	}
	model := modelspec.Model{
		Descriptor: modelspec.ModelDescriptor{
			Name:    c.component.Name,
			Version: c.component.Version,
		},
		ModelFS: modelspec.ModelFS{
			Type:    "layers",
			DiffIDs: diffIDs,
		},
	}
	data, err := json.Marshal(model)
	if err != nil {
		return componentManifest{}, err
	}
	config, err := transfer.PushBytes(ctx, target, data, modelspec.MediaTypeModelConfig, "model config", opts.Progress)
	if err != nil {
		return componentManifest{}, fmt.Errorf("push model config: %w", err)
	}
	desc, err := pushManifest(ctx, target, modelspec.ArtifactTypeModelManifest, config, descs, nil)
	if err != nil {
		return componentManifest{}, err
	}
	mapped := c.mapFiles(descs)
	files := transfer.ComponentFiles{
		Purl:  c.component.PackageURL,
		Files: mapped,
	}
	manifest := componentManifest{
		desc:  desc,
		files: files,
	}
	return manifest, nil
}

// packedComponent is a component as its plugin packed it (see
// transfer.Packer): an artifact in its kind's own registry format, pushed
// as it is, and restored file by file: the files of its directory that
// are the artifact's blobs from those blobs, and the rest, its extras,
// from blobs of their own.
type packedComponent struct {
	component cdx.Component
	// manifest is the artifact's manifest, and blobs every blob of it,
	// the manifest included, by digest.
	manifest ocispec.Descriptor
	blobs    packedBlobs
	// uploads are the artifact's blobs that aren't manifests.
	uploads []blobPlan
	// files are the files of the component's directory that are the
	// artifact's blobs.
	files []transfer.FileBlob
	// extras are the rest of its files.
	extras fileBlobs
}

// newPackedComponent plans component as packed, its artifact, whose blobs
// are files in dir, where build pulled it, or, for those the plugin built,
// inline. Every other file in dir is an extra.
func newPackedComponent(component cdx.Component, dir string, packed pluginlib.PackResult) (packedComponent, error) {
	if !slices.Contains(transfer.ManifestMediaTypes, packed.Manifest.MediaType) {
		return packedComponent{}, fmt.Errorf("pack: manifest %s is a %s, not a manifest", packed.Manifest.Digest, packed.Manifest.MediaType)
	}
	c := packedComponent{
		component: component,
		blobs:     packedBlobs{},
	}

	// claimedBy maps each file in dir that is one of the pack's blobs to it.
	claimedBy := map[string]ocispec.Descriptor{}
	manifest, err := c.addBlob(*packed.Manifest, dir, claimedBy)
	if err != nil {
		return packedComponent{}, err
	}
	c.manifest = manifest
	for _, blob := range packed.Blobs {
		if _, err := c.addBlob(blob, dir, claimedBy); err != nil {
			return packedComponent{}, err
		}
	}

	if err := c.planFiles(dir, claimedBy); err != nil {
		return packedComponent{}, err
	}
	return c, nil
}

// addBlob checks blob, one of the pack's, and adds it to c's blobs,
// returning its descriptor. If it's a file in dir, claimedBy records it as
// that file's, refusing a file two blobs claim. If it's a file and no
// manifest, it's one of c's uploads: CopyGraph pushes a manifest, as a
// manifest, and an inline blob, which is small, itself.
func (c *packedComponent) addBlob(blob pluginlib.PackedBlob, dir string, claimedBy map[string]ocispec.Descriptor) (ocispec.Descriptor, error) {
	desc, err := c.blobs.add(blob, dir)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack: %w", err)
	}
	if relative, inDir := relativePath(dir, blob.Path); inDir {
		if claimed, isClaimed := claimedBy[relative]; isClaimed && claimed.Digest != desc.Digest {
			return ocispec.Descriptor{}, fmt.Errorf("pack: %s is claimed by both blob %s and %s", relative, claimed.Digest, desc.Digest)
		}
		claimedBy[relative] = desc
	}
	if blob.Path != "" && !slices.Contains(transfer.ManifestMediaTypes, desc.MediaType) {
		upload := blobPlan{
			component: c.component,
			path:      blob.Path,
			desc:      desc,
		}
		c.uploads = append(c.uploads, upload)
	}
	return desc, nil
}

// planFiles sorts the files of dir, the component's directory, into those
// claimedBy says are the artifact's blobs, c's files, and the rest, c's
// extras, each planned as a blob of its own.
func (c *packedComponent) planFiles(dir string, claimedBy map[string]ocispec.Descriptor) error {
	files, err := listFiles(dir)
	if err != nil {
		return err
	}
	var extras []transfer.TarFile
	for _, file := range files {
		desc, isClaimed := claimedBy[file.Path]
		if !isClaimed {
			extras = append(extras, file)
			continue
		}
		fileBlob := transfer.NewFileBlob(file.Path, file.Mode, desc)
		c.files = append(c.files, fileBlob)
	}
	c.extras = newFileBlobs(c.component, dir, extras, nil)
	return nil
}

func (c packedComponent) layers() []blobPlan {
	extraPlans := c.extras.layers()
	return slices.Concat(c.uploads, extraPlans)
}

// pushManifest copies the artifact's manifests to target with
// oras.CopyGraph, which pushes what a manifest names before the manifest,
// and skips what target already has: every blob that isn't a manifest,
// pushed as one of c's layers.
func (c packedComponent) pushManifest(ctx context.Context, target oras.Target, descs []ocispec.Descriptor, opts transfer.Options) (componentManifest, error) {
	copyOpts := oras.CopyGraphOptions{
		Concurrency: opts.Concurrency,
	}
	if err := oras.CopyGraph(ctx, c.blobs, target, c.manifest, copyOpts); err != nil {
		return componentManifest{}, fmt.Errorf("push %s: %w", c.manifest.Digest, err)
	}

	extras := descs[len(c.uploads):]
	extraFiles := c.extras.mapFiles(extras)
	mapped := slices.Concat(c.files, extraFiles)
	sortFiles(mapped)
	files := transfer.ComponentFiles{
		Purl:  c.component.PackageURL,
		Files: mapped,
	}

	desc := c.manifest
	desc.ArtifactType = c.blobs.artifactType(ctx, c.manifest)
	manifest := componentManifest{
		desc:   desc,
		files:  files,
		extras: extras,
	}
	return manifest, nil
}

// packedBlobs are a PackResult's blobs, by digest: a read-only content
// store over the files that hold them, or their inline data.
type packedBlobs map[digest.Digest]pluginlib.PackedBlob

// add adds blob to b, returning its descriptor, after checking that it's a
// sha256 digest of either a file within input that holds exactly its size,
// or inline data, no more than pluginlib.MaxInlineBlobSize, that is
// exactly it.
func (b packedBlobs) add(blob pluginlib.PackedBlob, input string) (ocispec.Descriptor, error) {
	parsed, err := digest.Parse(blob.Digest)
	if err != nil || parsed.Algorithm() != digest.SHA256 {
		return ocispec.Descriptor{}, fmt.Errorf("blob %q: digest isn't sha256", blob.Digest)
	}
	if (blob.Path == "") == (blob.Data == nil) {
		return ocispec.Descriptor{}, fmt.Errorf("blob %s: want a path or inline data, not both or neither", blob.Digest)
	}
	if blob.Data != nil {
		if err := checkInline(blob, parsed); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("blob %s: %w", blob.Digest, err)
		}
	} else if err := checkFile(blob, input); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("blob %s: %w", blob.Digest, err)
	}
	b[parsed] = blob
	desc := ocispec.Descriptor{
		MediaType: blob.MediaType,
		Digest:    parsed,
		Size:      blob.Size,
	}
	return desc, nil
}

// checkInline checks blob's inline data is no more than
// pluginlib.MaxInlineBlobSize, and exactly its size and parsed, its
// digest.
func checkInline(blob pluginlib.PackedBlob, parsed digest.Digest) error {
	if len(blob.Data) > pluginlib.MaxInlineBlobSize {
		return fmt.Errorf("%d bytes inline, more than the %d allowed", len(blob.Data), pluginlib.MaxInlineBlobSize)
	}
	if int64(len(blob.Data)) != blob.Size || digest.FromBytes(blob.Data) != parsed {
		return errors.New("inline data isn't the blob")
	}
	return nil
}

// checkFile checks blob's file is within input, and a regular file of its
// size; the target checks its digest as it's pushed.
func checkFile(blob pluginlib.PackedBlob, input string) error {
	if _, inInput := relativePath(input, blob.Path); !inInput {
		return fmt.Errorf("%s is outside %s", blob.Path, input)
	}
	info, err := os.Lstat(blob.Path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != blob.Size {
		return fmt.Errorf("%s isn't a file of %d bytes", blob.Path, blob.Size)
	}
	return nil
}

// Fetch opens desc's bytes: its inline data, or the file holding them,
// read no further than its size.
func (b packedBlobs) Fetch(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	blob, ok := b[desc.Digest]
	if !ok {
		return nil, fmt.Errorf("%s: %w: the pack lists no such blob", desc.Digest, errdef.ErrNotFound)
	}
	if blob.Data != nil {
		reader := bytes.NewReader(blob.Data)
		return io.NopCloser(reader), nil
	}
	file, err := os.Open(blob.Path)
	if err != nil {
		return nil, err
	}
	limited := limitedFile{
		Reader: io.LimitReader(file, blob.Size),
		Closer: file,
	}
	return limited, nil
}

// Exists reports whether the pack lists desc.
func (b packedBlobs) Exists(_ context.Context, desc ocispec.Descriptor) (bool, error) {
	_, ok := b[desc.Digest]
	return ok, nil
}

// artifactType returns the artifact type manifest declares, if b can read
// it, for the package index to name: none for an image or a Helm chart.
func (b packedBlobs) artifactType(ctx context.Context, manifest ocispec.Descriptor) string {
	if manifest.Size > maxManifestSize {
		return ""
	}
	rc, err := b.Fetch(ctx, manifest)
	if err != nil {
		return ""
	}
	defer rc.Close()
	var declared struct {
		ArtifactType string `json:"artifactType"`
	}
	if err := json.NewDecoder(rc).Decode(&declared); err != nil {
		return ""
	}
	return declared.ArtifactType
}

// maxManifestSize bounds the packed manifest artifactType reads.
const maxManifestSize = 4 << 20

// limitedFile is a file read for no more than the size it was listed at,
// in case it has grown since.
type limitedFile struct {
	io.Reader
	io.Closer
}

// relativePath returns path relative to dir, "/"-separated, and whether
// it's inside dir.
func relativePath(dir, path string) (string, bool) {
	relative, err := filepath.Rel(dir, path)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return "", false
	}
	return filepath.ToSlash(relative), true
}

// sortFiles sorts files by path, as the files map lists them.
func sortFiles(files []transfer.FileBlob) {
	slices.SortFunc(files, func(a, b transfer.FileBlob) int { return strings.Compare(a.Path, b.Path) })
}

// pushEmptyConfig pushes the empty config an artifact without one names
// (see ocispec.DescriptorEmptyJSON).
func pushEmptyConfig(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	empty := ocispec.DescriptorEmptyJSON
	data := strings.NewReader(string(empty.Data))
	if err := transfer.PushBlob(ctx, target, empty, data, "empty config", nil); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push empty config: %w", err)
	}
	empty.Data = nil
	return empty, nil
}

// pushManifest pushes an OCI manifest of artifactType, config, and layers,
// with annotations, returning its descriptor, its artifact type set. It's
// built here rather than with oras.PackManifest, which annotates every
// manifest with the time it was packed, so pushing unchanged content gives
// the same digest.
func pushManifest(ctx context.Context, target oras.Target, artifactType string, config ocispec.Descriptor, layers []ocispec.Descriptor, annotations map[string]string) (ocispec.Descriptor, error) {
	if layers == nil {
		layers = []ocispec.Descriptor{}
	}
	manifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       config,
		Layers:       layers,
		Annotations:  annotations,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc, err := transfer.PushBytes(ctx, target, data, ocispec.MediaTypeImageManifest, "manifest", nil)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push manifest: %w", err)
	}
	desc.ArtifactType = artifactType
	return desc, nil
}
