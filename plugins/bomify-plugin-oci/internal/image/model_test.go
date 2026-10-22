package image

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// rawManifest is a manifest pushed byte for byte, as a model's own tool
// (modctl, kit, docker model) pushes one.
type rawManifest struct {
	data      []byte
	mediaType types.MediaType
}

func (m rawManifest) RawManifest() ([]byte, error)        { return m.data, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return m.mediaType, nil }

// TestPullAndPackAModelArtifact covers a model published as an OCI
// artifact rather than an image (ModelPack, a KitOps ModelKit, a Docker
// Model Runner model): an image manifest whose config isn't an image
// config, with an artifact type and a raw weights layer. Pull saves it as
// it is, and Pack describes it as it is, so its digest survives a push.
func TestPullAndPackAModelArtifact(t *testing.T) {
	host := newTestRegistry(t)
	ref := host + "/models/tiny:1.0"
	repository, err := name.NewRepository(host + "/models/tiny")
	if err != nil {
		t.Fatal(err)
	}

	config := static.NewLayer([]byte(`{"descriptor":{"name":"tiny"},"modelfs":{"type":"layers","diffIds":[]}}`), "application/vnd.cncf.model.config.v1+json")
	weights := static.NewLayer(bytes.Repeat([]byte("w"), 1<<20), "application/vnd.cncf.model.weight.v1.raw")
	var descriptors []string
	for _, blob := range []v1.Layer{config, weights} {
		if err := remote.WriteLayer(repository, blob); err != nil {
			t.Fatalf("push blob: %v", err)
		}
		descriptor, err := descriptorJSON(blob)
		if err != nil {
			t.Fatal(err)
		}
		descriptors = append(descriptors, descriptor)
	}
	manifestData := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":"application/vnd.cncf.model.manifest.v1+json","config":%s,"layers":[%s]}`, descriptors[0], descriptors[1]))
	reference, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	manifest := rawManifest{
		data:      manifestData,
		mediaType: types.OCIManifestSchema1,
	}
	if err := remote.Put(reference, manifest); err != nil {
		t.Fatalf("push manifest: %v", err)
	}
	want := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(manifestData),
		Size:      int64(len(manifestData)),
	}

	outputDir := t.TempDir()
	pulled, err := Pull(ref, outputDir, testLogger(), nil)
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if pulled.Hash.Value != want.Digest.Encoded() {
		t.Errorf("Pull's hash = %s, want the artifact's own digest, %s", pulled.Hash.Value, want.Digest)
	}
	saved, err := os.ReadFile(blobPath(outputDir, want))
	if err != nil {
		t.Fatalf("the layout lacks the manifest: %v", err)
	}
	if !bytes.Equal(saved, manifestData) {
		t.Errorf("the layout's manifest =\n%s\nwant it as pushed:\n%s", saved, manifestData)
	}

	packed, err := Pack(outputDir, testLogger())
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if packed.Manifest == nil || packed.Manifest.Digest != want.Digest.String() {
		t.Fatalf("packed manifest = %+v, want the artifact's own, %s", packed.Manifest, want.Digest)
	}
	var blobTypes []string
	for _, blob := range packed.Blobs {
		blobTypes = append(blobTypes, blob.MediaType)
	}
	wantTypes := []string{"application/vnd.cncf.model.config.v1+json", "application/vnd.cncf.model.weight.v1.raw"}
	if !slices.Equal(blobTypes, wantTypes) {
		t.Errorf("packed blobs = %v, want the model's config and weights, %v", blobTypes, wantTypes)
	}
}

// descriptorJSON returns blob's descriptor, as a manifest names it.
func descriptorJSON(blob v1.Layer) (string, error) {
	hash, err := blob.Digest()
	if err != nil {
		return "", err
	}
	size, err := blob.Size()
	if err != nil {
		return "", err
	}
	mediaType, err := blob.MediaType()
	if err != nil {
		return "", err
	}
	descriptor := fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":%d}`, mediaType, hash, size)
	return descriptor, nil
}
