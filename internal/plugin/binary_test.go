package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/testutil"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// binaryComponent returns a PurlType component for purl whose binary is
// the distribution external reference src.
func binaryComponent(purl, src string, hashes ...cdx.Hash) cdx.Component {
	c := cdx.Component{
		Name:               "plugin",
		PackageURL:         purl,
		ExternalReferences: &[]cdx.ExternalReference{{Type: cdx.ERTypeDistribution, URL: src}},
	}
	if len(hashes) > 0 {
		c.Hashes = &hashes
	}
	return c
}

// writeBinary writes content to a file named name in a fresh directory,
// returning that directory and the content's SHA-256.
func writeBinary(t *testing.T, name, content string) (dir, sum string) {
	t.Helper()

	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256([]byte(content))
	return dir, hex.EncodeToString(s[:])
}

func TestParseBinary(t *testing.T) {
	tests := []struct {
		purl    string
		want    Binary
		ok      bool
		wantErr bool
	}{
		{purl: "pkg:bomify-plugin/oci@v1.2.0?os=linux&arch=amd64", want: Binary{Kind: "oci", Version: "v1.2.0", OS: "linux", Arch: "amd64"}, ok: true},
		{purl: "pkg:bomify-plugin/generic", want: Binary{Kind: "generic"}, ok: true},
		{purl: "pkg:oci/nginx@1.27", ok: false},
		{purl: "", ok: false},
		{purl: "pkg:bomify-plugin/team/oci@v1", wantErr: true},
		{purl: "not a purl", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			got, ok, err := ParseBinary(cdx.Component{PackageURL: tt.purl})
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if ok != tt.ok || got != tt.want {
				t.Errorf("ParseBinary() = %+v, %v, want %+v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestBinaryMatchesAndFileName(t *testing.T) {
	b := Binary{Kind: "oci", OS: "windows", Arch: "amd64"}
	if !b.Matches("windows", "amd64") || b.Matches("linux", "amd64") || b.Matches("windows", "arm64") {
		t.Errorf("Matches() wrong for %+v", b)
	}
	if got, want := b.FileName(), "bomify-plugin-oci.exe"; got != want {
		t.Errorf("FileName() = %q, want %q", got, want)
	}

	any := Binary{Kind: "script"}
	if !any.Matches("darwin", "arm64") {
		t.Error("a binary with no os/arch qualifiers should match every platform")
	}
	if got, want := any.FileName(), "bomify-plugin-script"; got != want {
		t.Errorf("FileName() = %q, want %q", got, want)
	}
}

func TestBinarySource(t *testing.T) {
	sbomDir := t.TempDir()
	abs := filepath.Join(t.TempDir(), "bomify-plugin-oci")

	fileURL := "file://" + filepath.ToSlash(abs)
	if runtime.GOOS == "windows" {
		fileURL = "file:///" + filepath.ToSlash(abs)
	}

	tests := []struct {
		src     string
		want    string
		wantErr bool
	}{
		{src: "bin/bomify-plugin-oci", want: filepath.Join(sbomDir, "bin", "bomify-plugin-oci")},
		{src: abs, want: abs},
		{src: fileURL, want: abs},
		{src: "https://example.com/bomify-plugin-oci", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			got, err := BinarySource(binaryComponent("pkg:bomify-plugin/oci", tt.src), sbomDir)
			if (err != nil) != tt.wantErr {
				t.Fatalf("BinarySource() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("BinarySource() = %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := BinarySource(cdx.Component{PackageURL: "pkg:bomify-plugin/oci"}, sbomDir); err == nil {
		t.Error("BinarySource() for a component with no distribution reference: want error")
	}
}

func TestPullBinary(t *testing.T) {
	srcDir, sum := writeBinary(t, "plugin-linux", "#!/bin/sh\necho hi\n")
	baseDir := t.TempDir()
	component := binaryComponent("pkg:bomify-plugin/oci@v1?os=linux&arch=amd64", "plugin-linux",
		cdx.Hash{Algorithm: cdx.HashAlgoSHA256, Value: sum})

	result, err := PullBinary(component, srcDir, baseDir)
	if err != nil {
		t.Fatalf("PullBinary() error = %v", err)
	}
	if result.Hash.Value != sum {
		t.Errorf("Hash = %q, want %q", result.Hash.Value, sum)
	}

	want := filepath.Join(layout.ComponentLayer(baseDir, component.PackageURL), "bomify-plugin-oci")
	if result.OutputPath != want {
		t.Errorf("OutputPath = %q, want %q", result.OutputPath, want)
	}
	if data, err := os.ReadFile(want); err != nil || string(data) != "#!/bin/sh\necho hi\n" {
		t.Errorf("copied binary = %q, %v", data, err)
	}
	if _, err := os.Stat(layout.ComponentManifest(baseDir, component.PackageURL)); err != nil {
		t.Errorf("no manifest written: %v", err)
	}

	// A second pull reuses the first rather than copying again.
	again, err := PullBinary(component, srcDir, baseDir)
	if err != nil {
		t.Fatalf("second PullBinary() error = %v", err)
	}
	if again.Message != "reused prior pull" {
		t.Errorf("second PullBinary() Message = %q, want reuse", again.Message)
	}
}

func TestPullBinaryHashMismatch(t *testing.T) {
	srcDir, _ := writeBinary(t, "plugin", "binary")
	baseDir := t.TempDir()
	component := binaryComponent("pkg:bomify-plugin/oci@v1", "plugin",
		cdx.Hash{Algorithm: cdx.HashAlgoSHA256, Value: strings.Repeat("0", 64)})

	if _, err := PullBinary(component, srcDir, baseDir); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("PullBinary() error = %v, want a hash mismatch", err)
	}
	if _, err := os.Stat(layout.ComponentLayer(baseDir, component.PackageURL)); !os.IsNotExist(err) {
		t.Errorf("component directory left behind after a failed pull: %v", err)
	}
}

func TestCheckBinary(t *testing.T) {
	srcDir, sum := writeBinary(t, "plugin", "binary")
	good := binaryComponent("pkg:bomify-plugin/oci", "plugin", cdx.Hash{Algorithm: cdx.HashAlgoSHA256, Value: sum})
	if _, err := CheckBinary(good, srcDir); err != nil {
		t.Errorf("CheckBinary() error = %v", err)
	}

	missing := binaryComponent("pkg:bomify-plugin/oci", "nope")
	if _, err := CheckBinary(missing, srcDir); err == nil {
		t.Error("CheckBinary() for a missing binary: want error")
	}
}

func TestFindInstalled(t *testing.T) {
	dir := t.TempDir()
	path := testutil.InstallFakePlugin(t, dir, "fake")

	got, err := Find(dir, "fake", pluginlib.ComponentContract)
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if got != path {
		t.Errorf("Find() = %q, want %q", got, path)
	}

	if err := os.Mkdir(filepath.Join(dir, ExecutableName("dir", runtime.GOOS)), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(dir, "dir", pluginlib.ComponentContract); err == nil {
		t.Error("Find() for a directory: want error")
	}
}
