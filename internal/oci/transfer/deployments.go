package transfer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

// A package's deployments (see plugins/contracts/deployment/v1/CONTRACT.md)
// travel in its index as one more manifest, after its components, of
// DeploymentsArtifactType: an empty config, and as layers its deployment
// file and the templates that names, each of DeploymentFileMediaType,
// titled with its path. Being in the index, they're part of the package's
// digest, and so of what its signature covers. A bomify that doesn't know
// them ignores the entry, as it ignores any entry neither the SBOM's nor a
// component's.
const (
	DeploymentsArtifactType = "application/vnd.bomify.deployments.v1+json"
	DeploymentFileMediaType = "application/vnd.bomify.deployment.file.v1"
)

// maxDeploymentFileSize and maxDeploymentFiles bound what bomify reads of
// a package's deployments, which come from whoever published it: a
// deployment file and its templates are small.
const (
	maxDeploymentFileSize = 4 << 20
	maxDeploymentFiles    = 1000
)

// FetchDeployments fetches the deployments manifest desc names from
// target, and writes each of its files, checked against its digest, into
// dir, which must be empty, at the path it's titled with. It fails on a
// file that isn't of DeploymentFileMediaType, whose path isn't inside dir
// (see isSafePath), or given twice, or on one larger than allowed.
func FetchDeployments(ctx context.Context, target content.Fetcher, desc ocispec.Descriptor, dir string) error {
	var manifest ocispec.Manifest
	if err := fetchJSON(ctx, target, desc, maxManifestSize, &manifest); err != nil {
		return fmt.Errorf("fetch deployments manifest %s: %w", desc.Digest, err)
	}
	if manifest.ArtifactType != DeploymentsArtifactType {
		return fmt.Errorf("deployments manifest %s is of artifact type %q", desc.Digest, manifest.ArtifactType)
	}
	if len(manifest.Layers) > maxDeploymentFiles {
		return fmt.Errorf("deployments manifest %s has %d files, more than the %d allowed", desc.Digest, len(manifest.Layers), maxDeploymentFiles)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	paths := map[string]bool{}
	for _, layer := range manifest.Layers {
		path := layer.Annotations[ocispec.AnnotationTitle]
		if layer.MediaType != DeploymentFileMediaType {
			return fmt.Errorf("deployments manifest %s: file %q is of media type %q", desc.Digest, path, layer.MediaType)
		}
		if !isSafePath(path) {
			return fmt.Errorf("deployments manifest %s: file %q is outside its deployments", desc.Digest, path)
		}
		if paths[path] {
			return fmt.Errorf("deployments manifest %s names %s more than once", desc.Digest, path)
		}
		paths[path] = true
		if layer.Size > maxDeploymentFileSize {
			return fmt.Errorf("deployments manifest %s: %s is %d bytes, larger than the %d allowed", desc.Digest, path, layer.Size, maxDeploymentFileSize)
		}

		data, err := content.FetchAll(ctx, target, layer)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", path, err)
		}
		name := filepath.FromSlash(path)
		if err := root.MkdirAll(filepath.Dir(name), DirPerm); err != nil {
			return err
		}
		if err := root.WriteFile(name, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
