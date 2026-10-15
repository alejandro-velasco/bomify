package chart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	helmchart "helm.sh/helm/v4/pkg/chart/v2"
	"helm.sh/helm/v4/pkg/chart/v2/loader"
	"helm.sh/helm/v4/pkg/registry"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// Pack describes the chart a prior Pull wrote into inputDir as Helm stores
// a chart in a registry, as `helm push` builds one (see
// registry.Client.Push): its Chart.yaml, as JSON, as the config, and the
// archive as it is as the one layer, annotated as Helm annotates one,
// plus annotations, bomify's. It writes the config and manifest into
// outputDir. The archive must be the chart ref names.
func Pack(inputDir, outputDir string, ref Ref, annotations map[string]string, logger *slog.Logger) (*plugin.PackResult, error) {
	archivePath := filepath.Join(inputDir, ref.Filename())
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, err
	}
	loaded, err := loader.LoadArchive(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", ref.Filename(), err)
	}
	meta := loaded.Metadata
	if meta.Name != ref.Name || meta.Version != ref.Version {
		return nil, fmt.Errorf("%s holds chart %s %s, not the purl's %s %s", ref.Filename(), meta.Name, meta.Version, ref.Name, ref.Version)
	}

	configData, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	config, err := writeBlob(outputDir, "config.json", registry.ConfigMediaType, configData)
	if err != nil {
		return nil, err
	}
	layer := blobOf(registry.ChartLayerMediaType, archive, archivePath)

	manifest := ocispec.Manifest{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		Config:      descriptorOf(config),
		Layers:      []ocispec.Descriptor{descriptorOf(layer)},
		Annotations: chartAnnotations(meta, annotations),
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	manifestBlob, err := writeBlob(outputDir, "manifest.json", ocispec.MediaTypeImageManifest, manifestData)
	if err != nil {
		return nil, err
	}
	logger.Info("packed chart", "chart", meta.Name, "version", meta.Version, "digest", manifestBlob.Digest)

	result := plugin.PackResult{
		Manifest: &manifestBlob,
		Blobs:    []plugin.PackedBlob{config, layer},
	}
	return &result, nil
}

// chartAnnotations returns the annotations of the manifest of a chart,
// meta, as Helm annotates one (see registry.Client.Push): its description,
// name as title, version, home as URL, first source, and maintainers as
// authors, created when annotations says, then the chart's own
// annotations but for title and version, then annotations themselves.
func chartAnnotations(meta *helmchart.Metadata, annotations map[string]string) map[string]string {
	chartAnnotations := map[string]string{}
	add := func(key, value string) {
		if strings.TrimSpace(value) != "" {
			chartAnnotations[key] = value
		}
	}
	add(ocispec.AnnotationDescription, meta.Description)
	add(ocispec.AnnotationTitle, meta.Name)
	add(ocispec.AnnotationVersion, meta.Version)
	add(ocispec.AnnotationURL, meta.Home)
	if len(meta.Sources) > 0 {
		add(ocispec.AnnotationSource, meta.Sources[0])
	}
	var authors []string
	for _, maintainer := range meta.Maintainers {
		author := maintainer.Name
		if maintainer.Email != "" {
			author += " (" + maintainer.Email + ")"
		}
		authors = append(authors, author)
	}
	add(ocispec.AnnotationAuthors, strings.Join(authors, ", "))

	for key, value := range meta.Annotations {
		if key != ocispec.AnnotationTitle && key != ocispec.AnnotationVersion {
			chartAnnotations[key] = value
		}
	}
	maps.Copy(chartAnnotations, annotations)
	return chartAnnotations
}

// writeBlob writes data, of mediaType, into dir as name, returning it as a
// pack's blob.
func writeBlob(dir, name, mediaType string, data []byte) (plugin.PackedBlob, error) {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return plugin.PackedBlob{}, err
	}
	return blobOf(mediaType, data, path), nil
}

// blobOf returns data, of mediaType and held by the file at path, as a
// pack's blob.
func blobOf(mediaType string, data []byte, path string) plugin.PackedBlob {
	blob := plugin.PackedBlob{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data).String(),
		Size:      int64(len(data)),
		Path:      path,
	}
	return blob
}

// descriptorOf returns blob's descriptor, as a manifest names it.
func descriptorOf(blob plugin.PackedBlob) ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType: blob.MediaType,
		Digest:    digest.Digest(blob.Digest),
		Size:      blob.Size,
	}
	return desc
}
