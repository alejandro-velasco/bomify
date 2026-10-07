package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/signature"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

func TestPluginReference(t *testing.T) {
	tests := []struct {
		registry, name string
		want           string
		wantErr        bool
	}{
		{registry: defaultPluginRegistry, name: "oci", want: "ghcr.io/alejandro-velasco/bomify/plugins/oci:latest"},
		{registry: defaultPluginRegistry, name: "grype:1.12.0", want: "ghcr.io/alejandro-velasco/bomify/plugins/grype:1.12.0"},
		{registry: "registry.example.com/plugins/", name: "oci@sha256:abc", want: "registry.example.com/plugins/oci@sha256:abc"},
		{registry: "localhost:5000/plugins", name: "my-plugin", want: "localhost:5000/plugins/my-plugin:latest"},
		{registry: defaultPluginRegistry, name: "Oci", wantErr: true},
		{registry: defaultPluginRegistry, name: "../oci", wantErr: true},
		{registry: defaultPluginRegistry, name: "oci:", wantErr: true},
		{registry: "", name: "oci", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pluginReference(tt.registry, tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("pluginReference() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("pluginReference() = %q, want %q", got, tt.want)
			}
		})
	}
}

// fakeVerifier is the fake plugin (see testutil), built once for every
// installFakeVerifier to copy.
var fakeVerifier struct {
	once sync.Once
	data []byte
	err  error
}

// installFakeVerifier installs the fake plugin as bomify-plugin-sigstore
// into baseDir's plugins directory. pluginInstallPolicy only asks it
// which contract versions it speaks (see plugin.Find); nothing here signs
// or verifies with it.
func installFakeVerifier(t *testing.T, baseDir string) {
	t.Helper()

	fakeVerifier.once.Do(func() {
		bin := testutil.InstallFakePlugin(t, os.TempDir(), "bomify-cmd-test-verifier")
		fakeVerifier.data, fakeVerifier.err = os.ReadFile(bin)
		os.Remove(bin)
	})
	if fakeVerifier.err != nil {
		t.Fatal(fakeVerifier.err)
	}

	dir := layout.Plugins(baseDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, plugin.ExecutableName(pluginVerifier, runtime.GOOS)), fakeVerifier.data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// brokenVerifier puts a directory where bomify-plugin-sigstore belongs,
// so finding it fails for a reason other than its contract versions.
func brokenVerifier(t *testing.T, baseDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(layout.Plugins(baseDir), plugin.ExecutableName(pluginVerifier, runtime.GOOS)), 0o755); err != nil {
		t.Fatal(err)
	}
}

// installOutdatedVerifier installs a bomify-plugin-sigstore that speaks a
// signing contract version bomify doesn't.
func installOutdatedVerifier(t *testing.T, baseDir string) {
	t.Helper()
	t.Setenv("FAKEPLUGIN_CONTRACTS", `{"signing":0}`)
	installFakeVerifier(t, baseDir)
}

func TestIsDigestReference(t *testing.T) {
	const hex = "0000000000000000000000000000000000000000000000000000000000000000"
	for ref, want := range map[string]bool{
		"ghcr.io/org/plugins/oci@sha256:" + hex:       true,
		"ghcr.io/org/plugins/oci:1.0@sha256:" + hex:   true,
		"ghcr.io/org/plugins/oci@sha512:" + hex + hex: true,
		"ghcr.io/org/plugins/oci:1.0":                 false,
		"ghcr.io/org/plugins/oci":                     false,
		"ghcr.io/org/plugins/oci@sha256:zz":           false,
		"ghcr.io/org/plugins/oci@sha256:" + hex[:10]:  false,
		"ghcr.io/org/plugins/oci@md5:" + hex[:32]:     false,
	} {
		if got := isDigestReference(ref); got != want {
			t.Errorf("isDigestReference(%q) = %v, want %v", ref, got, want)
		}
	}
}

func TestPluginInstallPolicy(t *testing.T) {
	const (
		tagRef    = "ghcr.io/alejandro-velasco/bomify/plugins/oci:latest"
		digestRef = "ghcr.io/alejandro-velasco/bomify/plugins/oci@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	)
	logger := slog.New(slog.DiscardHandler)

	origDataDir := dataDir
	t.Cleanup(func() { dataDir = origDataDir })

	orgSigner := []signature.Signer{{Kind: pluginVerifier, Options: []string{"key=org.pub"}}}
	trustRule := func(match string) func(t *testing.T, baseDir string) {
		return func(t *testing.T, baseDir string) {
			installFakeVerifier(t, baseDir)
			if err := signature.SetRule(baseDir, signature.Rule{Match: match, Signers: orgSigner}); err != nil {
				t.Fatal(err)
			}
		}
	}
	keyPolicy := &signature.Policy{Verifier: signature.Plugin{Kind: pluginVerifier, Options: []string{"key=cosign.pub"}}}

	tests := []struct {
		name       string
		ref        string
		setup      func(t *testing.T, baseDir string)
		opts       pluginInstallOptions
		wantPolicy *signature.Policy
		wantErr    bool
	}{
		// Nothing vouches for a tag with no signer configured — not even on
		// bomify's own registry, which has no built-in signer — so it's
		// refused rather than installed unauthenticated.
		{name: "nothing configured, sigstore missing", opts: pluginInstallOptions{verify: true}, wantErr: true},
		{name: "nothing configured, sigstore installed", setup: installFakeVerifier, opts: pluginInstallOptions{verify: true}, wantErr: true},
		// A digest pin names the exact content, so it needs no signer: how
		// sigstore itself is bootstrapped.
		{name: "digest pin, sigstore missing", ref: digestRef, opts: pluginInstallOptions{verify: true}},
		{name: "digest pin, sigstore installed", ref: digestRef, setup: installFakeVerifier, opts: pluginInstallOptions{verify: true}},
		// A malformed digest pins nothing, so it needs a signer like a tag.
		{name: "malformed digest pin", ref: "ghcr.io/alejandro-velasco/bomify/plugins/oci@sha256:zz", setup: installFakeVerifier, opts: pluginInstallOptions{verify: true}, wantErr: true},
		{name: "verify options with sigstore installed", setup: installFakeVerifier, opts: pluginInstallOptions{verify: true, verifyOptions: []string{"key=cosign.pub"}}, wantPolicy: keyPolicy},
		{name: "verify options without sigstore", opts: pluginInstallOptions{verify: true, verifyOptions: []string{"key=cosign.pub"}}, wantErr: true},
		{name: "malformed verify option", setup: installFakeVerifier, opts: pluginInstallOptions{verify: true, verifyOptions: []string{"cosign.pub"}}, wantErr: true},
		{
			name: "matching trust rule", setup: trustRule("ghcr.io/alejandro-velasco"),
			opts:       pluginInstallOptions{verify: true},
			wantPolicy: &signature.Policy{Rules: signature.Config{{Match: "ghcr.io/alejandro-velasco", Signers: orgSigner}}},
		},
		{name: "verify options override a matching trust rule", setup: trustRule("ghcr.io/alejandro-velasco"), opts: pluginInstallOptions{verify: true, verifyOptions: []string{"key=cosign.pub"}}, wantPolicy: keyPolicy},
		{name: "trust rule for another registry", setup: trustRule("registry.example.com"), opts: pluginInstallOptions{verify: true}, wantErr: true},
		{name: "trust rule for another registry, digest pin", ref: digestRef, setup: trustRule("registry.example.com"), opts: pluginInstallOptions{verify: true}},
		{name: "verify=false ignores a matching trust rule", setup: trustRule(""), opts: pluginInstallOptions{verify: false}},
		{name: "verify=false with verify options", setup: installFakeVerifier, opts: pluginInstallOptions{verify: false, verifyOptions: []string{"key=cosign.pub"}}, wantErr: true},
		// A verifier that can't be used is only replaced by digest pin, as
		// it was first installed.
		{name: "outdated sigstore", setup: installOutdatedVerifier, opts: pluginInstallOptions{verify: true}, wantErr: true},
		{name: "outdated sigstore, digest pin", ref: digestRef, setup: installOutdatedVerifier, opts: pluginInstallOptions{verify: true}},
		{name: "outdated sigstore, verify options", ref: digestRef, setup: installOutdatedVerifier, opts: pluginInstallOptions{verify: true, verifyOptions: []string{"key=cosign.pub"}}, wantErr: true},
		// Anything else wrong with the verifier isn't a reason to skip it.
		{name: "something else in sigstore's place, digest pin", ref: digestRef, setup: brokenVerifier, opts: pluginInstallOptions{verify: true}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir = newDataDir(t)
			if tt.setup != nil {
				tt.setup(t, dataDir)
			}

			ref := tt.ref
			if ref == "" {
				ref = tagRef
			}
			policy, err := pluginInstallPolicy(ref, &tt.opts, logger)
			if (err != nil) != tt.wantErr {
				t.Fatalf("pluginInstallPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(policy, tt.wantPolicy) {
				t.Errorf("pluginInstallPolicy() = %+v, want %+v", policy, tt.wantPolicy)
			}
		})
	}
}

// writePluginSBOM writes a binary and an SBOM describing it as a
// pkg:bomify-plugin component for the host platform into a fresh
// directory, returning the SBOM's path and the component.
func writePluginSBOM(t *testing.T) (string, cdx.Component) {
	t.Helper()

	dir := t.TempDir()
	content := []byte("fake plugin binary")
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "fake"), content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)

	component := cdx.Component{
		Type:               cdx.ComponentTypeApplication,
		Name:               "bomify-plugin-fake",
		Version:            "v1.0.0",
		PackageURL:         "pkg:bomify-plugin/fake@v1.0.0?arch=" + runtime.GOARCH + "&os=" + runtime.GOOS,
		Hashes:             &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: hex.EncodeToString(sum[:])}},
		ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeDistribution, URL: "bin/fake"}},
	}

	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{component}

	path := filepath.Join(dir, "sbom.cdx.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := cdx.NewBOMEncoder(f, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		t.Fatal(err)
	}

	return path, component
}

func TestBuildPluginPackage(t *testing.T) {
	baseDir := newDataDir(t)
	sbomPath, component := writePluginSBOM(t)

	// No plugin is installed at all: bomify handles the component itself.
	if _, err := runRootCmd(t, baseDir, "build", sbomPath, "--check"); err != nil {
		t.Fatalf("build --check: %v", err)
	}
	if _, err := build.ResolveTag(baseDir, "fake:v1.0.0"); err == nil {
		t.Fatal("build --check recorded a build")
	}

	if _, err := runRootCmd(t, baseDir, "build", sbomPath, "--tag", "fake:v1.0.0"); err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := build.ResolveTag(baseDir, "fake:v1.0.0"); err != nil {
		t.Errorf("build not tagged: %v", err)
	}

	binary := filepath.Join(layout.ComponentLayer(baseDir, component.PackageURL), plugin.ExecutableName("fake", runtime.GOOS))
	if data, err := os.ReadFile(binary); err != nil || string(data) != "fake plugin binary" {
		t.Errorf("plugin binary in package = %q, %v", data, err)
	}

	// distribute has nowhere to send a plugin binary, and needs no plugin
	// to skip it.
	if _, err := runRootCmd(t, baseDir, "distribute", "fake:v1.0.0"); err != nil {
		t.Errorf("distribute: %v", err)
	}
}

func TestPluginListCmd(t *testing.T) {
	baseDir := newDataDir(t)

	out, err := runRootCmd(t, baseDir, "plugin", "list")
	if err != nil {
		t.Fatalf("plugin list: %v", err)
	}
	if strings.TrimSpace(out) != "NAME   VERSION   SOURCE" {
		t.Errorf("plugin list with nothing installed = %q", out)
	}

	installFakeVerifier(t, baseDir)
	out, err = runRootCmd(t, baseDir, "plugin", "list")
	if err != nil {
		t.Fatalf("plugin list: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || strings.Join(strings.Fields(lines[1]), " ") != "sigstore - -" {
		t.Errorf("plugin list = %q, want sigstore listed as unmanaged", out)
	}
}
