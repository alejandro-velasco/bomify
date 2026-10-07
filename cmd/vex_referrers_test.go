package cmd

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/signature"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// saveWithVEX saves hookTag with an OpenVEX document attached stating
// CVE-HIGH doesn't affect its component, plus extra flags (e.g. --sign).
func saveWithVEX(t *testing.T, extra ...string) string {
	t.Helper()
	baseDir := setUpHookPackage(t)
	testutil.InstallFakePlugin(t, layout.Plugins(baseDir), "fakesign")
	archive := filepath.Join(t.TempDir(), "app.tar")
	args := append([]string{"save", hookTag, "--output", archive, "--vex", writeOpenVEX(t)}, extra...)
	if _, err := runRootCmd(t, baseDir, args...); err != nil {
		t.Fatalf("save --vex: %v", err)
	}
	return archive
}

// loadDir returns a fresh data directory with the fake scanner and
// signer installed, ready to load into.
func loadDir(t *testing.T) string {
	t.Helper()
	dir := newDataDir(t)
	usePlugin(t, dir, "grype")
	testutil.InstallFakePlugin(t, layout.Plugins(dir), "fakesign")
	return dir
}

func TestLoadHonorsVerifiedPublisherVEX(t *testing.T) {
	archive := saveWithVEX(t, "--sign", "fakesign", "--sign-option", "key=k")
	verified := []string{"--verify", "fakesign", "--verify-option", "key=k"}

	// Verified: the publisher's VEX exempts CVE-HIGH, so a high bar passes.
	destDir := loadDir(t)
	if _, err := runRootCmd(t, destDir, append([]string{"load", "--input", archive, "--scan", "grype", "--fail-on", "high"}, verified...)...); err != nil {
		t.Fatalf("verified load: error = %v, want the publisher's VEX to exempt CVE-HIGH", err)
	}
	if _, err := build.ResolveTag(destDir, hookTag); err != nil {
		t.Errorf("tag not recorded: %v", err)
	}

	// Not verified: the same VEX is ignored, so CVE-HIGH fails the gate.
	if _, err := runRootCmd(t, loadDir(t), "load", "--input", archive, "--scan", "grype", "--fail-on", "high"); !isGateError(err) {
		t.Errorf("unverified load: error = %v, want a gate failure (VEX ignored)", err)
	}

	// VEX only exempts what it names: CVE-LOW still fails a low bar.
	if _, err := runRootCmd(t, loadDir(t), append([]string{"load", "--input", archive, "--scan", "grype", "--fail-on", "low"}, verified...)...); !isGateError(err) {
		t.Errorf("verified load at low: error = %v, want CVE-LOW to fail", err)
	}
}

// TestPublisherVEXNeedsItsOwnSignature covers a package that's signed
// and verifies, but whose VEX was attached afterwards, unsigned: the VEX
// is ignored rather than trusted on the package's word.
func TestPublisherVEXNeedsItsOwnSignature(t *testing.T) {
	ctx := context.Background()
	baseDir := setUpHookPackage(t)
	testutil.InstallFakePlugin(t, layout.Plugins(baseDir), "fakesign")

	signer, err := signature.NewSigner(layout.Plugins(baseDir), signature.Plugin{Kind: "fakesign", Options: []string{"key=k"}}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sbomHash, err := build.ResolveTag(baseDir, hookTag)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	stage := t.TempDir()
	store, err := oci.New(stage)
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	pushed, err := push.Push(ctx, store, hookTag, baseDir, sbomHash, transfer.Options{Sign: signer})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	doc, err := security.ReadVEX(baseDir, writeOpenVEX(t))
	if err != nil {
		t.Fatalf("ReadVEX: %v", err)
	}
	if _, _, err := transfer.Attach(ctx, store, pushed.Manifest, doc.Attachment(), nil); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	archive := filepath.Join(t.TempDir(), "app.tar")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	if err := errors.Join(transfer.WriteTar(stage, f), f.Close()); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	_, err = runRootCmd(t, loadDir(t), "load", "--input", archive, "--scan", "grype", "--fail-on", "high",
		"--verify", "fakesign", "--verify-option", "key=k")
	if !isGateError(err) {
		t.Errorf("load: error = %v, want the package to verify but the unsigned VEX to be ignored, failing the gate", err)
	}
}

func TestPublishVEXFlagAcceptsStoredNames(t *testing.T) {
	baseDir := setUpHookPackage(t)
	if _, err := runRootCmd(t, baseDir, "security", "vex", "add", "team", writeOpenVEX(t)); err != nil {
		t.Fatalf("vex add: %v", err)
	}
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", hookTag, "--output", archive, "--vex", "team"); err != nil {
		t.Errorf("save --vex <stored name>: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "save", hookTag, "--output", archive, "--vex", "missing"); err == nil {
		t.Error("save --vex <neither a stored name nor a file>: error = nil, want one")
	}
}
