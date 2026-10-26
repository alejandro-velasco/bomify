package cmd

import (
	"archive/tar"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// retagArchive returns a copy of archive, a "bomify save" tarball, with
// every tag renamed to tag, as whoever built a tarball can.
func retagArchive(t *testing.T, archive, tag string) string {
	t.Helper()
	dir := t.TempDir()
	in, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := transfer.ExtractTar(tar.NewReader(in), dir); err != nil {
		t.Fatalf("extract %s: %v", archive, err)
	}

	indexPath := filepath.Join(dir, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	for _, manifest := range index.Manifests {
		if _, ok := manifest.Annotations[ocispec.AnnotationRefName]; ok {
			manifest.Annotations[ocispec.AnnotationRefName] = tag
		}
	}
	if data, err = json.Marshal(index); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "retagged.tar")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := transfer.WriteTar(dir, f); err != nil {
		t.Fatalf("archive: %v", err)
	}
	return out
}

// TestLoadTrustRuleCantBeEscapedByTag covers a tarball renaming an
// unsigned package so that no trust rule matches it: a tarball's tags
// come from whoever built it, so once rules exist, one matching none
// fails rather than loading unverified.
func TestLoadTrustRuleCantBeEscapedByTag(t *testing.T) {
	baseDir := setUpHookPackage(t)
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", hookTag, "--output", archive); err != nil {
		t.Fatalf("save: %v", err)
	}
	destDir := loadDir(t)
	if _, err := runRootCmd(t, destDir, "trust", "create", "fakesign", "--match", "registry.example.com/team", "--option", "key=k"); err != nil {
		t.Fatalf("trust create: %v", err)
	}

	for _, tag := range []string{
		hookTag,
		"app:1.0",
		"REGISTRY.example.com/team/app:1.0",
		"registry.example.com./team/app:1.0",
		"registry.example.com:443/team/app:1.0",
		"other.example.com/team/app:1.0",
	} {
		if _, err := runRootCmd(t, destDir, "load", "--input", retagArchive(t, archive, tag)); err == nil {
			t.Errorf("load of an unsigned package tagged %q: error = nil, want it refused", tag)
		}
	}

	// --insecure-skip-verify still restores it, deliberately.
	if _, err := runRootCmd(t, destDir, "load", "--input", retagArchive(t, archive, "app:1.0"), "--insecure-skip-verify"); err != nil {
		t.Errorf("load --insecure-skip-verify: %v", err)
	}
}

// TestLoadTrustRuleMatchesEverySpelling covers a signed package whose tag
// writes its registry another way: the rule still applies, and verifies.
func TestLoadTrustRuleMatchesEverySpelling(t *testing.T) {
	archive := saveWithVEX(t, "--sign", "fakesign", "--sign-option", "key=k")
	destDir := loadDir(t)
	if _, err := runRootCmd(t, destDir, "trust", "create", "fakesign", "--match", "registry.example.com/team", "--option", "key=k"); err != nil {
		t.Fatalf("trust create: %v", err)
	}
	if _, err := runRootCmd(t, destDir, "load", "--input", retagArchive(t, archive, "REGISTRY.example.com:443/team/app:1.0")); err != nil {
		t.Errorf("load of a signed package under another spelling of its registry: %v", err)
	}
}
