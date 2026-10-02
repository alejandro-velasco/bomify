package cmd

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/provenance"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// buildWithProvenance builds a one-component package from a local file,
// offline, with --provenance, tagged app:1.0, and returns its data
// directory and the component's SHA-256.
func buildWithProvenance(t *testing.T) (string, string) {
	t.Helper()
	baseDir := t.TempDir()
	testutil.InstallFakePlugin(t, layout.Plugins(baseDir), "fakesign")

	src := t.TempDir()
	binary := []byte("plugin binary")
	if err := os.WriteFile(filepath.Join(src, "bin"), binary, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"application","name":"x",
		"purl":"pkg:bomify-plugin/x@v1.0.0","externalReferences":[{"type":"distribution","url":"bin"}]}]}`
	sbomPath := filepath.Join(src, "app.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(sbom), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := runRootCmd(t, baseDir, "build", sbomPath, "--tag", "app:1.0", "--provenance"); err != nil {
		t.Fatalf("build --provenance: %v", err)
	}
	return baseDir, hex.EncodeToString(sum[:])
}

// provenanceIn opens the tarball at archive and returns the in-toto
// statement or envelope bytes of app:1.0's provenance referrer, and the
// referrer itself.
func provenanceIn(t *testing.T, archive string) (ocispec.Descriptor, ocispec.Descriptor, []byte) {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := transfer.ExtractTar(tar.NewReader(f), dir); err != nil {
		t.Fatal(err)
	}
	store, err := oci.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	manifest, err := store.Resolve(ctx, "app:1.0")
	if err != nil {
		t.Fatal(err)
	}
	referrers, err := transfer.Referrers(ctx, store, manifest, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range referrers {
		if r.Annotations[transfer.AnnotationAttestation] != provenance.PredicateType {
			continue
		}
		var m ocispec.Manifest
		data, err := content.FetchAll(ctx, store, r)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &m); err != nil || len(m.Layers) != 1 {
			t.Fatalf("provenance referrer manifest: %v, %d layers", err, len(m.Layers))
		}
		layer, err := content.FetchAll(ctx, store, m.Layers[0])
		if err != nil {
			t.Fatal(err)
		}
		return manifest, r, layer
	}
	t.Fatalf("no provenance referrer among %d referrers", len(referrers))
	return ocispec.Descriptor{}, ocispec.Descriptor{}, nil
}

func TestBuildProvenanceSavedUnsigned(t *testing.T) {
	baseDir, componentSum := buildWithProvenance(t)
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", "app:1.0", "--output", archive); err != nil {
		t.Fatalf("save: %v", err)
	}

	manifest, referrer, layer := provenanceIn(t, archive)
	if referrer.ArtifactType != provenance.MediaType {
		t.Errorf("unsigned provenance artifact type = %q, want %q", referrer.ArtifactType, provenance.MediaType)
	}
	var s struct {
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate struct {
			BuildDefinition struct {
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(layer, &s); err != nil {
		t.Fatalf("statement: %v", err)
	}
	if s.Subject[0].Name != "app" || s.Subject[0].Digest["sha256"] != manifest.Digest.Encoded() {
		t.Errorf("subject = %+v, want the saved package", s.Subject)
	}
	found := false
	for _, d := range s.Predicate.BuildDefinition.ResolvedDependencies {
		if d.URI == "pkg:bomify-plugin/x@v1.0.0" && d.Digest["sha256"] == componentSum {
			found = true
		}
	}
	if !found {
		t.Errorf("resolvedDependencies = %+v, want the component and its SHA-256", s.Predicate.BuildDefinition.ResolvedDependencies)
	}
}

func TestBuildProvenanceSavedSigned(t *testing.T) {
	baseDir, _ := buildWithProvenance(t)
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", "app:1.0", "--output", archive, "--sign", "fakesign", "--sign-option", "key=k"); err != nil {
		t.Fatalf("save --sign: %v", err)
	}

	_, referrer, layer := provenanceIn(t, archive)
	var envelope map[string]string
	if err := json.Unmarshal(layer, &envelope); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if envelope["payloadType"] != provenance.MediaType {
		t.Errorf("provenance signed with payload type %q, want %q", envelope["payloadType"], provenance.MediaType)
	}
	if referrer.Annotations[provenance.AnnotationStatement] == "" {
		t.Errorf("referrer annotations = %v, want the statement's digest", referrer.Annotations)
	}

	// The attestation, signed with the same plugin, mustn't break
	// verifying the package's own signature.
	destDir := t.TempDir()
	testutil.InstallFakePlugin(t, layout.Plugins(destDir), "fakesign")
	if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--verify", "fakesign", "--verify-option", "key=k"); err != nil {
		t.Errorf("load --verify: %v", err)
	}
}

func TestProvenancePrunedWithBuild(t *testing.T) {
	baseDir, _ := buildWithProvenance(t)
	matches, _ := filepath.Glob(filepath.Join(baseDir, "provenance", "*.json"))
	if len(matches) != 1 {
		t.Fatalf("provenance records = %v, want 1", matches)
	}
	if _, err := runRootCmd(t, baseDir, "rmp", "app:1.0"); err != nil {
		t.Fatalf("rmp: %v", err)
	}
	if _, err := os.Stat(matches[0]); !os.IsNotExist(err) {
		t.Errorf("provenance record survived its build being pruned: %v", err)
	}
}

func TestProvenanceRejectsCheck(t *testing.T) {
	if _, err := runRootCmd(t, t.TempDir(), "build", "x.json", "--check", "--provenance"); err == nil {
		t.Error("build --check --provenance: error = nil, want one")
	}
}
