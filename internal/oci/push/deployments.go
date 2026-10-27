package push

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// pushDeployments pushes the deployments recorded for the build of sbomHash
// under baseDir (see layout.Deployments), if there are any, as the
// package's deployments manifest (see transfer.DeploymentsArtifactType):
// each file a layer titled with its path, in path order, so unchanged
// deployments give the same manifest. It reports false if there are none.
func pushDeployments(ctx context.Context, target oras.Target, baseDir, sbomHash string, progress transfer.ProgressFunc) (ocispec.Descriptor, bool, error) {
	dir := layout.Deployments(baseDir, sbomHash)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return ocispec.Descriptor{}, false, nil
	}

	var layers []ocispec.Descriptor
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s isn't a regular file", path)
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		title := filepath.ToSlash(relative)
		layer, err := transfer.PushBytes(ctx, target, data, transfer.DeploymentFileMediaType, "deployments: "+title, progress)
		if err != nil {
			return fmt.Errorf("push %s: %w", title, err)
		}
		layer.Annotations = map[string]string{ocispec.AnnotationTitle: title}
		layers = append(layers, layer)
		return nil
	})
	if err != nil {
		return ocispec.Descriptor{}, false, fmt.Errorf("push deployments: %w", err)
	}

	config, err := pushEmptyConfig(ctx, target)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	desc, err := pushManifest(ctx, target, transfer.DeploymentsArtifactType, config, layers, nil)
	if err != nil {
		return ocispec.Descriptor{}, false, fmt.Errorf("push deployments: %w", err)
	}
	return desc, true, nil
}
