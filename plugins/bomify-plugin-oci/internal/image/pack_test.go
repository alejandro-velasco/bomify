package image

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestPackListsTheImageAsItIs(t *testing.T) {
	img, err := random.Image(1024, 2)
	if err != nil {
		t.Fatalf("random.Image: %v", err)
	}
	inputDir := t.TempDir()
	if err := crane.SaveOCI(img, inputDir); err != nil {
		t.Fatalf("SaveOCI: %v", err)
	}

	result, err := Pack(inputDir, testLogger())
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest == nil || result.Manifest.Digest != digest.String() {
		t.Fatalf("manifest = %+v, want the image's own, %s", result.Manifest, digest)
	}
	configName, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{configName.String()}
	for _, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, layerDigest.String())
	}
	var got []string
	for _, blob := range append(result.Blobs, *result.Manifest) {
		if blob != *result.Manifest {
			got = append(got, blob.Digest)
		}
		// Every blob is the layout's own file, holding exactly its bytes.
		if !strings.HasPrefix(blob.Path, inputDir) {
			t.Errorf("blob %s is at %s, not in the layout", blob.Digest, blob.Path)
		}
		data, err := os.ReadFile(blob.Path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if "sha256:"+hex.EncodeToString(sum[:]) != blob.Digest || int64(len(data)) != blob.Size {
			t.Errorf("%s holds %d bytes of another digest, not blob %s's %d", filepath.Base(blob.Path), len(data), blob.Digest, blob.Size)
		}
	}
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		t.Errorf("blobs = %v, want the config and layers, %v", got, want)
	}
}

func TestPackRefusesALayoutOfSeveralImages(t *testing.T) {
	inputDir := t.TempDir()
	for range 2 {
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := crane.SaveOCI(img, inputDir); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Pack(inputDir, testLogger()); err == nil || !strings.Contains(err.Error(), "want one") {
		t.Errorf("Pack = %v, want a layout of two images refused", err)
	}
}

func TestPackRefusesALayoutOfAnIndex(t *testing.T) {
	index, err := random.Index(64, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	inputDir := t.TempDir()
	path, err := layout.Write(inputDir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := path.AppendIndex(index); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(inputDir, testLogger()); err == nil || !strings.Contains(err.Error(), "not an image manifest") {
		t.Errorf("Pack = %v, want a layout of an index refused", err)
	}
}
