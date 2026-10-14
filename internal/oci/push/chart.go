package push

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"sigs.k8s.io/yaml"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// Helm's types for a chart in a registry: what `helm push` writes and
// `helm pull` reads.
const (
	helmConfigMediaType = "application/vnd.cncf.helm.config.v1+json"
	helmChartMediaType  = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
)

// maxChartYAML bounds how much of a Chart.yaml publishChart reads.
const maxChartYAML = 1 << 20

// publishChart publishes the chart archive component's plugin stored as
// Helm stores a chart in a registry: its Chart.yaml, as JSON, as the
// config, and the archive as it is as the layer. It's annotated as `helm
// push` annotates one, but created when the package was, so publishing
// an unchanged package gives the same digest.
func (p componentPublisher) publishChart(ctx context.Context, target oras.Target, component componentLayers) (ocispec.Descriptor, error) {
	archivePath, err := chartArchive(component.dir())
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	metadata, err := readChartMetadata(archive)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("%s: %w", filepath.Base(archivePath), err)
	}

	config, err := transfer.PushBytes(ctx, target, metadata.config, helmConfigMediaType, "chart config", p.opts.Progress)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push config: %w", err)
	}
	label := component.component.PackageURL + componentRepositoryLabel
	layer, err := transfer.PushBytes(ctx, target, archive, helmChartMediaType, label, p.opts.Progress)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push chart: %w", err)
	}

	annotations := p.annotations(component.component)
	annotations[ocispec.AnnotationTitle] = metadata.Name
	annotations[ocispec.AnnotationVersion] = metadata.Version
	if metadata.Description != "" {
		annotations[ocispec.AnnotationDescription] = metadata.Description
	}
	packOpts := oras.PackManifestOptions{
		ConfigDescriptor:    &config,
		Layers:              []ocispec.Descriptor{layer},
		ManifestAnnotations: annotations,
	}
	desc, err := oras.PackManifest(ctx, target, oras.PackManifestVersion1_1, "", packOpts)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pack manifest: %w", err)
	}
	return desc, nil
}

// chartArchive returns the path of the one chart archive, a .tgz file, in
// dir.
func chartArchive(dir string) (string, error) {
	files, err := transfer.TarFiles(dir)
	if err != nil {
		return "", err
	}
	var archives []string
	for _, file := range files {
		if file.Mode.IsRegular() && strings.HasSuffix(file.Path, ".tgz") {
			archives = append(archives, file.Path)
		}
	}
	if len(archives) != 1 {
		return "", fmt.Errorf("the chart's directory holds %d chart archives, want one", len(archives))
	}
	return filepath.Join(dir, filepath.FromSlash(archives[0])), nil
}

// chartMetadata is a chart's Chart.yaml: as the JSON Helm keeps in a
// chart's config, and the fields its manifest is annotated with.
type chartMetadata struct {
	config      []byte
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// readChartMetadata reads the Chart.yaml at the top of archive, a chart's
// gzipped tar, where `helm package` puts it: <chart name>/Chart.yaml.
func readChartMetadata(archive []byte) (chartMetadata, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return chartMetadata{}, err
	}
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return chartMetadata{}, errors.New("no Chart.yaml")
		}
		if err != nil {
			return chartMetadata{}, err
		}
		if path.Base(header.Name) != "Chart.yaml" || strings.Count(strings.Trim(header.Name, "/"), "/") != 1 {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxChartYAML))
		if err != nil {
			return chartMetadata{}, err
		}
		return parseChartMetadata(data)
	}
}

// parseChartMetadata parses data, a Chart.yaml.
func parseChartMetadata(data []byte) (chartMetadata, error) {
	config, err := yaml.YAMLToJSON(data)
	if err != nil {
		return chartMetadata{}, fmt.Errorf("parse Chart.yaml: %w", err)
	}
	var metadata chartMetadata
	if err := json.Unmarshal(config, &metadata); err != nil {
		return chartMetadata{}, fmt.Errorf("parse Chart.yaml: %w", err)
	}
	if metadata.Name == "" || metadata.Version == "" {
		return chartMetadata{}, errors.New("no name or version in Chart.yaml")
	}
	metadata.config = config
	return metadata, nil
}
