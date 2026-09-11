package image

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/crane"

	"bomify/internal/plugin"
)

// Pull downloads ref and saves it as a tarball under outputDir.
func Pull(ref string, component cdx.Component, outputDir string) (*plugin.Result, error) {
	img, err := crane.Pull(ref)
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", ref, err)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir %s: %w", outputDir, err)
	}

	path := filepath.Join(outputDir, tarballName(component))
	if err := crane.Save(img, ref, path); err != nil {
		return nil, fmt.Errorf("save %s to %s: %w", ref, path, err)
	}

	return &plugin.Result{OutputPath: path, Message: fmt.Sprintf("pulled %s", ref)}, nil
}

// Push copies ref directly to a tag under remote, without a local copy.
func Push(ref string, component cdx.Component, remote string) (*plugin.Result, error) {
	dst := destinationReference(remote, component)

	if err := crane.Copy(ref, dst); err != nil {
		return nil, fmt.Errorf("copy %s to %s: %w", ref, dst, err)
	}

	return &plugin.Result{OutputPath: dst, Message: fmt.Sprintf("pushed %s to %s", ref, dst)}, nil
}

func tarballName(component cdx.Component) string {
	return fmt.Sprintf("%s-%s.tar", component.Name, versionOrLatest(component))
}

func destinationReference(remote string, component cdx.Component) string {
	remote = strings.TrimSuffix(remote, "/")
	return fmt.Sprintf("%s/%s:%s", remote, component.Name, versionOrLatest(component))
}
