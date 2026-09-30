package signature

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/oci/save"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// TestSaveLoadCarriesSignature proves a signature made by `bomify save
// --sign` travels inside the tarball as a referrer — surviving the OCI
// layout's own index.json round trip — and is enforced by `bomify load
// --verify` before anything is restored.
func TestSaveLoadCarriesSignature(t *testing.T) {
	installFakeSigner(t)
	ctx := context.Background()

	sourceDir := t.TempDir()
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sbomHash, _, err := build.RecordManifest(sourceDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	if err := build.UpdateRepositories(sourceDir, []string{"app:v1"}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	signer, err := NewSigner(pluginDir, Plugin{Kind: fakeKind, Options: []string{"key=secret"}}, discardLogger())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	var archive bytes.Buffer
	if err := save.Save(ctx, sourceDir, []string{"app:v1"}, &archive, 1, nil, transfer.Hooks{Sign: signer}, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}

	load := func(key string) (string, error) {
		destDir := t.TempDir()
		verifier := NewVerifier(pluginDir, Policy{Verifier: Plugin{Kind: fakeKind, Options: []string{"key=" + key}}}, discardLogger())
		_, err := save.Load(ctx, destDir, bytes.NewReader(archive.Bytes()), 1, nil, transfer.Hooks{Verify: verifier})
		return destDir, err
	}

	destDir, err := load("secret")
	if err != nil {
		t.Fatalf("Load with the signing key: %v", err)
	}
	if _, err := build.ResolveTag(destDir, "app:v1"); err != nil {
		t.Errorf("app:v1 not restored: %v", err)
	}

	destDir, err = load("other")
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("Load with the wrong key: %v, want a verification failure", err)
	}
	if entries, _ := os.ReadDir(destDir); len(entries) != 0 {
		t.Errorf("data dir has %d entries after a failed verify, want none", len(entries))
	}

	// And an unsigned save fails verification outright.
	archive.Reset()
	if err := save.Save(ctx, sourceDir, []string{"app:v1"}, &archive, 1, nil, transfer.Hooks{}, nil); err != nil {
		t.Fatalf("Save (unsigned): %v", err)
	}
	if _, err := load("secret"); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Fatalf("Load of an unsigned save: %v, want a no-signature error", err)
	}
}
