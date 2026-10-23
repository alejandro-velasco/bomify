package push

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// deploymentFiles are the deployments a build records in these tests.
var deploymentFiles = map[string]string{
	"deployments.yaml":        "deployments:\n  - name: web\n    type: helm\n    config: templates/web.yaml.tmpl\n",
	"templates/web.yaml.tmpl": "replicas: 2\n",
}

// writeDeployments records files as the deployments of the build of
// sbomHash under baseDir.
func writeDeployments(t *testing.T, baseDir, sbomHash string, files map[string]string) {
	t.Helper()
	dir := layout.Deployments(baseDir, sbomHash)
	for path, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPushAndPullCarryDeployments covers a build's deployments: push puts
// them in the index, after the components, the same each time, and pull
// restores them, so pushing again carries them on.
func TestPushAndPullCarryDeployments(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent})
	writeDeployments(t, baseDir, sbomHash, deploymentFiles)
	store := newStore(t)
	ctx := context.Background()
	tagPackage(t, baseDir, "pkg", sbomHash)

	first, err := Push(ctx, store, "pkg", baseDir, transfer.Options{})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	again, err := Push(ctx, store, "pkg", baseDir, transfer.Options{})
	if err != nil {
		t.Fatalf("Push again: %v", err)
	}
	if again.Manifest.Digest != first.Manifest.Digest {
		t.Errorf("pushing unchanged deployments again gave %s, want %s", again.Manifest.Digest, first.Manifest.Digest)
	}

	_, pkg := fetchPackage(t, store, "pkg")
	if pkg.Deployments.Digest == "" || pkg.Deployments.ArtifactType != transfer.DeploymentsArtifactType {
		t.Fatalf("index deployments = %+v, want the deployments manifest", pkg.Deployments)
	}
	last := pkg.Index.Manifests[len(pkg.Index.Manifests)-1]
	if last.Digest != pkg.Deployments.Digest {
		t.Errorf("index's last entry is %s, want the deployments manifest after the components", last.Digest)
	}

	pulledDir := t.TempDir()
	if _, err := pull.Pull(ctx, store, "pkg", pulledDir, transfer.Options{}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	restored := layout.Deployments(pulledDir, sbomHash)
	for path, want := range deploymentFiles {
		got, err := os.ReadFile(filepath.Join(restored, filepath.FromSlash(path)))
		if err != nil || string(got) != want {
			t.Errorf("restored %s = %q, %v, want %q", path, got, err, want)
		}
	}
}

func TestPushWithoutDeploymentsHasNone(t *testing.T) {
	baseDir := t.TempDir()
	writeLayer(t, baseDir, dataComponent, map[string]string{"a.txt": "a"})
	sbomHash := recordSBOM(t, baseDir, []cdx.Component{dataComponent})
	store := newStore(t)
	tagPackage(t, baseDir, "pkg", sbomHash)

	if _, err := Push(context.Background(), store, "pkg", baseDir, transfer.Options{}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	_, pkg := fetchPackage(t, store, "pkg")
	if pkg.Deployments.Digest != "" {
		t.Errorf("deployments = %v, want none", pkg.Deployments.Digest)
	}
	for _, entry := range pkg.Index.Manifests {
		if entry.ArtifactType == transfer.DeploymentsArtifactType {
			t.Errorf("index has a deployments manifest: %v", entry.Digest)
		}
	}
}

// TestDeploymentsManifestTitlesEachFile covers the manifest's layout:
// each file a layer of its own, titled with its path, in path order.
func TestDeploymentsManifestTitlesEachFile(t *testing.T) {
	baseDir := t.TempDir()
	writeDeployments(t, baseDir, "hash", deploymentFiles)
	store := newStore(t)

	desc, ok, err := pushDeployments(context.Background(), store, baseDir, "hash", nil)
	if err != nil || !ok {
		t.Fatalf("pushDeployments = %v, %v", ok, err)
	}

	manifest := fetchManifest(t, store, desc)
	var titles []string
	for _, layer := range manifest.Layers {
		if layer.MediaType != transfer.DeploymentFileMediaType {
			t.Errorf("layer %s is of %s", layer.Digest, layer.MediaType)
		}
		titles = append(titles, layer.Annotations[ocispec.AnnotationTitle])
	}
	if len(titles) != 2 || titles[0] != "deployments.yaml" || titles[1] != "templates/web.yaml.tmpl" {
		t.Errorf("titles = %q, want each file's path, in order", titles)
	}
	if manifest.Config.MediaType != ocispec.MediaTypeEmptyJSON {
		t.Errorf("config = %+v, want the empty one", manifest.Config)
	}
}
