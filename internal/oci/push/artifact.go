package push

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	modelspec "github.com/modelpack/model-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orasfile "oras.land/oras-go/v2/content/file"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/parallel"
)

// artifactPublisher publishes a component as an artifact of its files,
// which `oras pull` writes out as they are: its small files as one
// gzipped tar, titled "." and annotated for `oras pull` to unpack where
// it pulls to, then each large file as the package's own blob, titled
// with its path. A model is a ModelPack artifact.
type artifactPublisher struct{ componentPublication }

func (p artifactPublisher) publish(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	layers, diffIDs, err := p.pushLayers(ctx, target)
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	packOpts := oras.PackManifestOptions{
		Layers:              layers,
		ManifestAnnotations: p.annotations(),
	}
	artifactType := ComponentArtifactType
	if p.isModel() {
		artifactType = modelspec.ArtifactTypeModelManifest
		config, err := p.pushModelConfig(ctx, target, diffIDs)
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		packOpts.ConfigDescriptor = &config
	}
	desc, err := oras.PackManifest(ctx, target, oras.PackManifestVersion1_1, artifactType, packOpts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack manifest: %w", err)
	}
	desc.ArtifactType = artifactType
	return desc, nil
}

// isModel reports whether p's component is a model, published as a
// ModelPack artifact.
func (p artifactPublisher) isModel() bool {
	return p.component.Type == cdx.ComponentTypeMachineLearningModel
}

// pushLayers pushes the artifact's layers, its small files' tar (see
// pushTarGz) and then its large files (see pushFile), up to
// opts.Concurrency at once, returning them with their uncompressed
// digests, in order.
func (p artifactPublisher) pushLayers(ctx context.Context, target oras.Target) ([]ocispec.Descriptor, []digest.Digest, error) {
	smallFiles := p.smallFiles()
	largeFiles := p.largeFiles()

	var layers []ocispec.Descriptor
	var diffIDs []digest.Digest
	if len(smallFiles) > 0 {
		layer, tarDigest, err := p.pushTarGz(ctx, target, smallFiles)
		if err != nil {
			return nil, nil, err
		}
		layers = append(layers, layer)
		diffIDs = append(diffIDs, tarDigest)
	}

	pushFile := func(ctx context.Context, _ int, index int) (ocispec.Descriptor, error) {
		return p.pushFile(ctx, target, p.plans[index].(filePlan), p.descs[index])
	}
	fileLayers, err := parallel.Map(ctx, p.opts.Concurrency, largeFiles, pushFile)
	if err != nil {
		return nil, nil, err
	}
	for _, layer := range fileLayers {
		layers = append(layers, layer)
		diffIDs = append(diffIDs, layer.Digest)
	}
	return layers, diffIDs, nil
}

// pushFile pushes plan's large file, which the package pushed as packaged,
// as the artifact's layer of it (see fileLayer): the same blob, so it's
// mounted from the package's repository rather than uploaded where it can
// be (see transfer.MountBlob).
func (p artifactPublisher) pushFile(ctx context.Context, target oras.Target, plan filePlan, packaged ocispec.Descriptor) (ocispec.Descriptor, error) {
	desc := p.fileLayer(plan, packaged)
	path := filepath.Join(plan.dir, filepath.FromSlash(plan.file.Path))
	open := func() (io.ReadCloser, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		limited := limitedFile{
			Reader: io.LimitReader(file, desc.Size),
			Closer: file,
		}
		return limited, nil
	}
	label := transfer.LayerLabel(p.component.PackageURL, desc.Digest.Encoded()) + componentRepositoryLabel
	if err := transfer.MountBlob(ctx, target, desc, p.mountFrom(), open, label, p.opts.Progress); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", plan.file.Path, err)
	}
	return desc, nil
}

// fileLayer returns the descriptor of plan's large file, which the package
// pushed as packaged, as the artifact's layer: the same blob, titled with
// the file's path, so `oras pull` writes it out. A model's is a ModelPack
// weight.
func (p artifactPublisher) fileLayer(plan filePlan, packaged ocispec.Descriptor) ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType:   packaged.MediaType,
		Digest:      packaged.Digest,
		Size:        packaged.Size,
		Annotations: plan.file.Annotations(p.component.PackageURL),
	}
	desc.Annotations[ocispec.AnnotationTitle] = plan.file.Path
	if p.isModel() {
		desc.MediaType = modelspec.MediaTypeModelWeightRaw
		desc.Annotations[modelspec.AnnotationFilepath] = plan.file.Path
		// Large isn't proof of a weight.
		desc.Annotations[modelspec.AnnotationMediaTypeUntested] = "true"
	}
	return desc
}

// limitedFile is a file read for no more than the size it was hashed at,
// in case it has grown since.
type limitedFile struct {
	io.Reader
	io.Closer
}

// pushTarGz pushes files, small files of p's component's directory, as one
// gzipped tar (see tarLayer), returning its descriptor and the
// uncompressed tar's digest.
func (p artifactPublisher) pushTarGz(ctx context.Context, target oras.Target, files []transfer.TarFile) (ocispec.Descriptor, digest.Digest, error) {
	tmp, err := os.CreateTemp("", "bomify-push-component-*.tar.gz")
	if err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	compressedHasher, tarHasher := sha256.New(), sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(tmp, compressedHasher))
	if err := transfer.WriteTarTree(p.dir(), files, io.MultiWriter(gz, tarHasher)); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("archive %s: %w", p.dir(), err)
	}
	if err := gz.Close(); err != nil {
		return ocispec.Descriptor{}, "", err
	}
	size, err := tmp.Seek(0, io.SeekCurrent)
	if err != nil {
		return ocispec.Descriptor{}, "", err
	}
	compressed := digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(compressedHasher.Sum(nil)))
	tarDigest := digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(tarHasher.Sum(nil)))

	desc := p.tarLayer(compressed, size, tarDigest)
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return ocispec.Descriptor{}, "", err
	}
	label := transfer.Label(p.component.PackageURL, compressed.Encoded()) + componentRepositoryLabel
	if err := transfer.PushBlob(ctx, target, desc, tmp, label, p.opts.Progress); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("push layer: %w", err)
	}
	return desc, tarDigest, nil
}

// tarLayer returns the descriptor of the artifact's gzipped tar of small
// files, compressed and size long, tarDigest uncompressed: titled "." and
// annotated for `oras pull` to unpack where it pulls to, checking
// tarDigest. A model's is a ModelPack weight config.
func (p artifactPublisher) tarLayer(compressed digest.Digest, size int64, tarDigest digest.Digest) ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType: ComponentTarGzMediaType,
		Digest:    compressed,
		Size:      size,
		Annotations: map[string]string{
			ocispec.AnnotationTitle:   ".",
			orasfile.AnnotationUnpack: "true",
			orasfile.AnnotationDigest: tarDigest.String(),
			transfer.AnnotationPurl:   p.component.PackageURL,
		},
	}
	if p.isModel() {
		desc.MediaType = modelspec.MediaTypeModelWeightConfigGzip
		// Small files are a model's configuration, tokenizer, and docs,
		// mixed.
		desc.Annotations[modelspec.AnnotationMediaTypeUntested] = "true"
	}
	return desc
}

// pushModelConfig pushes p's component's ModelPack config, for layers
// whose uncompressed digests are diffIDs.
func (p artifactPublisher) pushModelConfig(ctx context.Context, target oras.Target, diffIDs []digest.Digest) (ocispec.Descriptor, error) {
	config := modelspec.Model{
		Descriptor: modelspec.ModelDescriptor{
			Name:    p.component.Name,
			Version: p.component.Version,
		},
		ModelFS: modelspec.ModelFS{
			Type:    "layers",
			DiffIDs: append([]digest.Digest{}, diffIDs...),
		},
	}
	data, err := json.Marshal(config)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc, err := transfer.PushBytes(ctx, target, data, modelspec.MediaTypeModelConfig, "model config", p.opts.Progress)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push config: %w", err)
	}
	return desc, nil
}
