package transfer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
)

// deploymentFile pushes data to store as a deployment file titled path.
func deploymentFile(t *testing.T, store *memory.Store, path, data string) ocispec.Descriptor {
	t.Helper()
	desc := ocispec.Descriptor{
		MediaType: DeploymentFileMediaType,
		Digest:    digest.FromString(data),
		Size:      int64(len(data)),
	}
	// Several files may share content, which the store holds once.
	if exists, _ := store.Exists(context.Background(), desc); !exists {
		desc = pushData(t, store, DeploymentFileMediaType, []byte(data))
	}
	desc.Annotations = map[string]string{ocispec.AnnotationTitle: path}
	return desc
}

// deploymentsManifest pushes a manifest of artifactType whose layers are
// layers to store.
func deploymentsManifest(t *testing.T, store *memory.Store, artifactType string, layers ...ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       ocispec.DescriptorEmptyJSON,
		Layers:       layers,
	}
	manifest.SchemaVersion = 2
	desc := pushJSON(t, store, ocispec.MediaTypeImageManifest, manifest)
	desc.ArtifactType = artifactType
	return desc
}

func TestFetchDeployments(t *testing.T) {
	store := memory.New()
	desc := deploymentsManifest(t, store, DeploymentsArtifactType,
		deploymentFile(t, store, "deployments.yaml", "deployments: []\n"),
		deploymentFile(t, store, "templates/web.yaml.tmpl", "replicas: 2\n"),
	)
	dir := t.TempDir()

	if err := FetchDeployments(context.Background(), store, desc, dir); err != nil {
		t.Fatalf("FetchDeployments: %v", err)
	}

	for path, want := range map[string]string{"deployments.yaml": "deployments: []\n", "templates/web.yaml.tmpl": "replicas: 2\n"} {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v, want %q", path, got, err, want)
		}
	}
}

func TestFetchDeploymentsRefuses(t *testing.T) {
	store := memory.New()
	file := deploymentFile(t, store, "deployments.yaml", "deployments: []\n")
	wrongType := pushData(t, store, FileMediaType, []byte("x"))
	wrongType.Annotations = map[string]string{ocispec.AnnotationTitle: "x"}
	huge := deploymentFile(t, store, "huge", "x")
	huge.Size = maxDeploymentFileSize + 1
	missing := ocispec.Descriptor{MediaType: DeploymentFileMediaType, Digest: digest.FromString("gone"), Size: 4, Annotations: map[string]string{ocispec.AnnotationTitle: "gone"}}
	many := make([]ocispec.Descriptor, maxDeploymentFiles+1)
	for index := range many {
		many[index] = file
	}

	for name, test := range map[string]struct {
		desc ocispec.Descriptor
		want string
	}{
		"another artifact type": {desc: deploymentsManifest(t, store, "application/vnd.other", file), want: "artifact type"},
		"a path outside":        {desc: deploymentsManifest(t, store, DeploymentsArtifactType, deploymentFile(t, store, "../escaped", "x")), want: "outside its deployments"},
		"an absolute path":      {desc: deploymentsManifest(t, store, DeploymentsArtifactType, deploymentFile(t, store, "/etc/passwd", "x")), want: "outside its deployments"},
		"no title":              {desc: deploymentsManifest(t, store, DeploymentsArtifactType, deploymentFile(t, store, "", "x")), want: "outside its deployments"},
		"a path twice":          {desc: deploymentsManifest(t, store, DeploymentsArtifactType, file, file), want: "more than once"},
		"another media type":    {desc: deploymentsManifest(t, store, DeploymentsArtifactType, wrongType), want: "media type"},
		"a file too large":      {desc: deploymentsManifest(t, store, DeploymentsArtifactType, huge), want: "larger than"},
		"too many files":        {desc: deploymentsManifest(t, store, DeploymentsArtifactType, many...), want: "more than the"},
		"a file it can't get":   {desc: deploymentsManifest(t, store, DeploymentsArtifactType, missing), want: "fetch gone"},
		"a manifest it can't get": {
			desc: ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("gone"), Size: 4},
			want: "fetch deployments manifest",
		},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "deployments")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}

			err := FetchDeployments(context.Background(), store, test.desc, dir)

			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("FetchDeployments = %v, want an error containing %q", err, test.want)
			}
			assertOnlyChild(t, parent, "deployments")
		})
	}
}

// assertOnlyChild fails t if parent holds anything but child.
func assertOnlyChild(t *testing.T, parent, child string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != child {
			t.Errorf("wrote %s outside its directory", entry.Name())
		}
	}
}

func TestFetchPackageFindsDeployments(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	sbom := sbomManifest(t, store, Files{})
	deployments := deploymentsManifest(t, store, DeploymentsArtifactType, deploymentFile(t, store, "deployments.yaml", "deployments: []\n"))

	pkg, err := FetchPackage(ctx, store, packageIndex(t, store, ArtifactType, sbom, component("pkg:oci/a@1"), deployments))
	if err != nil {
		t.Fatalf("FetchPackage: %v", err)
	}
	if pkg.Deployments.Digest != deployments.Digest || len(pkg.Components) != 1 {
		t.Errorf("deployments = %v, components %d, want the deployments manifest and one component", pkg.Deployments.Digest, len(pkg.Components))
	}

	_, err = FetchPackage(ctx, store, packageIndex(t, store, ArtifactType, sbom, deployments, deployments))
	if err == nil || !strings.Contains(err.Error(), "more than one deployments manifest") {
		t.Errorf("FetchPackage of two deployments manifests = %v, want an error", err)
	}
}
