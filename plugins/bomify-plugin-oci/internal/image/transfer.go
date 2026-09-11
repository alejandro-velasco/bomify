package image

import (
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/layout"

	"bomify/internal/plugin"
)

// Pull downloads ref and saves it into outputDir as an OCI Image Layout,
// so the pulled artifact is in OCI format rather than a docker-style
// tarball. outputDir is a directory bomify has already created dedicated
// to this component, so Pull writes directly into it.
func Pull(ref string, component cdx.Component, outputDir string) (*plugin.Result, error) {
	img, err := crane.Pull(ref)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}

	if err := crane.SaveOCI(img, outputDir); err != nil {
		return nil, fmt.Errorf("save %s to %s: %w", ref, outputDir, err)
	}

	return &plugin.Result{OutputPath: outputDir, Message: fmt.Sprintf("pulled %s", ref)}, nil
}

// Push reads the OCI Image Layout a prior Pull wrote into inputDir and
// pushes it to a tag under remote.
func Push(inputDir string, component cdx.Component, remote string) (*plugin.Result, error) {
	idx, err := layout.ImageIndexFromPath(inputDir)
	if err != nil {
		return nil, fmt.Errorf("read OCI layout at %s: %w", inputDir, err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read OCI layout manifest at %s: %w", inputDir, err)
	}
	if len(manifest.Manifests) == 0 {
		return nil, fmt.Errorf("no images found in OCI layout at %s", inputDir)
	}

	img, err := idx.Image(manifest.Manifests[0].Digest)
	if err != nil {
		return nil, fmt.Errorf("read image from OCI layout at %s: %w", inputDir, err)
	}

	dst := destinationReference(remote, component)
	if err := crane.Push(img, dst); err != nil {
		return nil, fmt.Errorf("push %s to %s: %w", inputDir, dst, err)
	}

	return &plugin.Result{OutputPath: dst, Message: fmt.Sprintf("pushed %s to %s", inputDir, dst)}, nil
}

func destinationReference(remote string, component cdx.Component) string {
	remote = strings.TrimSuffix(remote, "/")
	return fmt.Sprintf("%s/%s:%s", remote, component.Name, versionOrLatest(component))
}
