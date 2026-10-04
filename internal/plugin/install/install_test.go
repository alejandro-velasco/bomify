package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

const ref = "registry.example.com/plugins/fake:v1.0.0"

// platformBinary is one plugin binary a test package carries.
type platformBinary struct {
	os, arch, content string
}

// otherPlatform is a platform no test ever installs for, so a package
// carrying it alongside the host's proves Install picks the right one.
var otherPlatform = platformBinary{os: "plan9", arch: "mips", content: "not for this machine"}

// hostBinary is a binary built for the machine the tests run on.
func hostBinary(content string) platformBinary {
	return platformBinary{os: hostOS, arch: hostArch, content: content}
}

// packageOptions shape a test plugin package.
type packageOptions struct {
	// omitHashes leaves every component without a declared SHA-256.
	omitHashes bool
	// tamper, if non-empty, replaces the host binary's built layer content
	// after the build recorded its hash, so what's pushed no longer matches
	// what the SBOM declares.
	tamper string
	// contracts is every component's plugin.PropertyContracts: by default
	// {"component":1}, and none at all if "-".
	contracts string
}

// publishPackage builds a plugin package carrying binaries — exactly as
// "bomify build" would, through plugin.PullBinary — and pushes it into a
// fresh OCI layout as ref, returning that layout.
func publishPackage(t *testing.T, binaries []platformBinary, opts packageOptions) *oci.Store {
	t.Helper()
	ctx := context.Background()

	srcDir := t.TempDir()
	sourceDir := t.TempDir()

	var components []cdx.Component
	for _, b := range binaries {
		file := b.os + "-" + b.arch
		if err := os.WriteFile(filepath.Join(srcDir, file), []byte(b.content), 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(b.content))

		c := cdx.Component{
			Type:               cdx.ComponentTypeApplication,
			Name:               "bomify-plugin-fake",
			Version:            "v1.0.0",
			PackageURL:         "pkg:bomify-plugin/fake@v1.0.0?arch=" + b.arch + "&os=" + b.os,
			ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeDistribution, URL: file}},
		}
		if !opts.omitHashes {
			c.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: hex.EncodeToString(sum[:])}}
		}
		switch opts.contracts {
		case "":
			c.Properties = &[]cdx.Property{{Name: plugin.PropertyContracts, Value: `{"component":1}`}}
		case "-":
		default:
			c.Properties = &[]cdx.Property{{Name: plugin.PropertyContracts, Value: opts.contracts}}
		}
		components = append(components, c)
	}

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeApplication, Name: "fake"}}
	bom.Components = &components

	sbomPath := filepath.Join(srcDir, "sbom.cdx.json")
	f, err := os.Create(sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := cdx.NewBOMEncoder(f, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		t.Fatal(err)
	}
	f.Close()

	for _, c := range components {
		result, err := plugin.PullBinary(c, srcDir, sourceDir)
		if err != nil {
			t.Fatalf("PullBinary(%s): %v", c.PackageURL, err)
		}
		if opts.tamper != "" && strings.Contains(c.PackageURL, "os="+hostOS) {
			if err := os.WriteFile(result.OutputPath, []byte(opts.tamper), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}

	sbomHash, _, err := build.RecordManifest(sourceDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := push.Push(ctx, store, ref, sourceDir, sbomHash, transfer.Options{Concurrency: 1}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	return store
}

// installed returns the content of the plugin binary installed in
// dataDir for kind, failing the test if there isn't one.
func installed(t *testing.T, dataDir, kind string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(layout.Plugins(dataDir), plugin.ExecutableName(kind, hostOS)))
	if err != nil {
		t.Fatalf("plugin %s not installed: %v", kind, err)
	}
	return string(data)
}

// assertNothingInstalled fails the test if dataDir's plugins directory
// holds anything at all — a binary, the index, or a leftover staging
// directory.
func assertNothingInstalled(t *testing.T, dataDir string) {
	t.Helper()

	entries, err := os.ReadDir(layout.Plugins(dataDir))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("unexpected %s left in the plugins directory", e.Name())
	}
}

func TestInstallPicksHostBinary(t *testing.T) {
	store := publishPackage(t, []platformBinary{otherPlatform, hostBinary("host binary")}, packageOptions{})
	dataDir := t.TempDir()

	records, err := Install(context.Background(), store, ref, dataDir, Options{RequireChecksum: true})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}

	if got := installed(t, dataDir, "fake"); got != "host binary" {
		t.Errorf("installed binary = %q, want the host's", got)
	}

	sum := sha256.Sum256([]byte("host binary"))
	want := Record{Kind: "fake", Version: "v1.0.0", Reference: ref, SHA256: hex.EncodeToString(sum[:])}
	if len(records) != 1 || records[0] != want {
		t.Errorf("Install() = %+v, want [%+v]", records, want)
	}

	entries, err := List(dataDir)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Kind != "fake" || entries[0].Record == nil || *entries[0].Record != want {
		t.Errorf("List() = %+v, want the installed record", entries)
	}

	// Nothing but the binary and the index is left behind: no staging
	// directory, and no package recorded the way "bomify pull" would.
	files, _ := os.ReadDir(layout.Plugins(dataDir))
	for _, f := range files {
		if name := f.Name(); name != plugin.ExecutableName("fake", hostOS) && name != indexFile {
			t.Errorf("unexpected %s left in the plugins directory", name)
		}
	}
	if repos, _ := build.ReadRepositories(dataDir); len(repos) != 0 {
		t.Errorf("plugin package recorded as a local package: %v", repos)
	}
}

// fetchRecorder is a target that records the purl annotation of every
// descriptor fetched through it.
type fetchRecorder struct {
	oras.ReadOnlyTarget
	purls []string
}

func (r *fetchRecorder) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	if purl := desc.Annotations[transfer.AnnotationPurl]; purl != "" {
		r.purls = append(r.purls, purl)
	}
	return r.ReadOnlyTarget.Fetch(ctx, desc)
}

func TestInstallFetchesOnlyHostLayers(t *testing.T) {
	store := publishPackage(t, []platformBinary{otherPlatform, hostBinary("host binary")}, packageOptions{})
	recorder := &fetchRecorder{ReadOnlyTarget: store}

	if _, err := Install(context.Background(), recorder, ref, t.TempDir(), Options{RequireChecksum: true}); err != nil {
		t.Fatalf("Install() error = %v", err)
	}

	if len(recorder.purls) != 1 || !strings.Contains(recorder.purls[0], "os="+hostOS) {
		t.Errorf("fetched layers for %v, want only the host's", recorder.purls)
	}
}

func TestInstallReplacesEarlierInstall(t *testing.T) {
	dataDir := t.TempDir()

	for _, content := range []string{"first", "second"} {
		store := publishPackage(t, []platformBinary{hostBinary(content)}, packageOptions{})
		if _, err := Install(context.Background(), store, ref, dataDir, Options{RequireChecksum: true}); err != nil {
			t.Fatalf("Install(%s) error = %v", content, err)
		}
	}

	if got := installed(t, dataDir, "fake"); got != "second" {
		t.Errorf("installed binary = %q, want the second install's", got)
	}
}

func TestInstallNoBinaryForHost(t *testing.T) {
	store := publishPackage(t, []platformBinary{otherPlatform}, packageOptions{})
	dataDir := t.TempDir()

	_, err := Install(context.Background(), store, ref, dataDir, Options{RequireChecksum: true})
	if err == nil || !strings.Contains(err.Error(), "fake plan9/mips") {
		t.Fatalf("Install() error = %v, want one naming the available platforms", err)
	}
	assertNothingInstalled(t, dataDir)
}

func TestInstallRequiresDeclaredChecksum(t *testing.T) {
	store := publishPackage(t, []platformBinary{hostBinary("unhashed")}, packageOptions{omitHashes: true})

	dataDir := t.TempDir()
	if _, err := Install(context.Background(), store, ref, dataDir, Options{RequireChecksum: true}); err == nil {
		t.Fatal("Install() with RequireChecksum: want an error for a component declaring no SHA-256")
	}
	assertNothingInstalled(t, dataDir)

	dataDir = t.TempDir()
	if _, err := Install(context.Background(), store, ref, dataDir, Options{}); err != nil {
		t.Fatalf("Install() without RequireChecksum error = %v", err)
	}
	if got := installed(t, dataDir, "fake"); got != "unhashed" {
		t.Errorf("installed binary = %q", got)
	}
}

func TestInstallRejectsChecksumMismatch(t *testing.T) {
	store := publishPackage(t, []platformBinary{hostBinary("genuine")}, packageOptions{tamper: "tampered"})

	// Even with checksums not required, a declared one that doesn't match
	// is never installed.
	for _, required := range []bool{true, false} {
		dataDir := t.TempDir()
		_, err := Install(context.Background(), store, ref, dataDir, Options{RequireChecksum: required})
		if err == nil || !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("Install(RequireChecksum=%v) error = %v, want a checksum mismatch", required, err)
		}
		assertNothingInstalled(t, dataDir)
	}
}

func TestInstallVerifierFailureInstallsNothing(t *testing.T) {
	store := publishPackage(t, []platformBinary{hostBinary("unsigned")}, packageOptions{})
	dataDir := t.TempDir()

	errUnsigned := errors.New("no trusted signature")
	verify := func(context.Context, oras.ReadOnlyTarget, string, ocispec.Descriptor) error { return errUnsigned }

	if _, err := Install(context.Background(), store, ref, dataDir, Options{RequireChecksum: true, Verify: verify}); !errors.Is(err, errUnsigned) {
		t.Fatalf("Install() error = %v, want %v", err, errUnsigned)
	}
	assertNothingInstalled(t, dataDir)
}

func TestInstallChecksContractVersions(t *testing.T) {
	for name, tc := range map[string]struct {
		contracts string
		wantErr   string
	}{
		"another version": {contracts: `{"component":2}`, wantErr: "bomify needs component v1"},
		// A package built before plugins reported their contract versions
		// records none.
		"predates them": {contracts: "-", wantErr: "predates them"},
	} {
		t.Run(name, func(t *testing.T) {
			store := publishPackage(t, []platformBinary{hostBinary("incompatible")}, packageOptions{contracts: tc.contracts})
			dataDir := t.TempDir()

			_, err := Install(context.Background(), store, ref, dataDir, Options{RequireChecksum: true})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), `"bomify-plugin-fake"`) {
				t.Fatalf("Install() error = %v, want one naming the plugin and containing %q", err, tc.wantErr)
			}
			if !errors.Is(err, plugin.ErrIncompatible) {
				t.Errorf("Install() error = %v, want it to wrap plugin.ErrIncompatible", err)
			}
			assertNothingInstalled(t, dataDir)
		})
	}
}

func TestListIncludesUnmanagedBinaries(t *testing.T) {
	dataDir := t.TempDir()
	dir := layout.Plugins(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{plugin.ExecutableName("manual", hostOS), "README.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := List(dataDir)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Kind != "manual" || entries[0].Record != nil {
		t.Errorf("List() = %+v, want just the unmanaged plugin", entries)
	}

	if entries, err := List(t.TempDir()); err != nil || len(entries) != 0 {
		t.Errorf("List() with no plugins directory = %+v, %v", entries, err)
	}
}
