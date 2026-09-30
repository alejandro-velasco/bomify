package cmd

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/oci/push"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/signature"
)

// useFakeSigner builds internal/signature's fake signing plugin into
// baseDir as bomify-plugin-fakesign: its "signature" is an HMAC keyed by
// --option key=<secret>.
func useFakeSigner(t *testing.T, baseDir string) {
	t.Helper()
	bin := filepath.Join(plugin.Dir(baseDir), "bomify-plugin-fakesign")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../internal/signature/testdata/fakesigner").CombinedOutput(); err != nil {
		t.Fatalf("build fake signer: %v\n%s", err, out)
	}
}

// saveSignedWithVEX saves hookTag signed with key "k", with an OpenVEX
// document attached stating CVE-HIGH doesn't affect its component.
func saveSignedWithVEX(t *testing.T) string {
	t.Helper()
	baseDir := setUpHookPackage(t)
	useFakeSigner(t, baseDir)
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", hookTag, "--output", archive,
		"--sign", "fakesign", "--sign-option", "key=k", "--vex", writeOpenVEX(t)); err != nil {
		t.Fatalf("save --sign --vex: %v", err)
	}
	return archive
}

// loadDir returns a fresh data directory with the fake scanner and
// signer installed, ready to load into.
func loadDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	usePlugin(t, dir, "grype")
	useFakeSigner(t, dir)
	return dir
}

func TestLoadHonorsVerifiedPublisherVEX(t *testing.T) {
	archive := saveSignedWithVEX(t)

	// Verified: the publisher's VEX exempts CVE-HIGH, so a high bar passes.
	destDir := loadDir(t)
	if _, err := runRootCmd(t, destDir, "load", "--input", archive, "--scan", "grype", "--fail-on", "high",
		"--verify", "fakesign", "--verify-option", "key=k"); err != nil {
		t.Fatalf("verified load: error = %v, want the publisher's VEX to exempt CVE-HIGH", err)
	}
	if _, err := build.ResolveTag(destDir, hookTag); err != nil {
		t.Errorf("tag not recorded: %v", err)
	}

	// Not verified: the same VEX is ignored, so CVE-HIGH fails the gate.
	unverifiedDir := loadDir(t)
	if _, err := runRootCmd(t, unverifiedDir, "load", "--input", archive, "--scan", "grype", "--fail-on", "high"); !isGateError(err) {
		t.Errorf("unverified load: error = %v, want a gate failure (VEX ignored)", err)
	}

	// VEX only exempts what it names: CVE-LOW still fails a low bar.
	lowDir := loadDir(t)
	if _, err := runRootCmd(t, lowDir, "load", "--input", archive, "--scan", "grype", "--fail-on", "low",
		"--verify", "fakesign", "--verify-option", "key=k"); !isGateError(err) {
		t.Errorf("verified load at low: error = %v, want CVE-LOW to fail", err)
	}
}

// TestPublisherVEXNeedsItsOwnSignature covers a package that verifies
// but whose attached VEX doesn't: the VEX is ignored rather than
// trusted on the package's word.
func TestPublisherVEXNeedsItsOwnSignature(t *testing.T) {
	baseDir := setUpHookPackage(t)
	useFakeSigner(t, baseDir)
	origDataDir := dataDir
	t.Cleanup(func() { dataDir = origDataDir })
	dataDir = baseDir

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	key := signature.Plugin{Kind: "fakesign", Options: []string{"key=k"}}

	signer, err := signature.NewSigner(plugin.Dir(baseDir), key, logger)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	sbomHash, err := build.ResolveTag(baseDir, hookTag)
	if err != nil {
		t.Fatalf("ResolveTag: %v", err)
	}
	pushed, err := push.Push(ctx, store, hookTag, baseDir, sbomHash, 1, nil, transfer.Hooks{Sign: signer}, nil)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	vexData, err := os.ReadFile(writeOpenVEX(t))
	if err != nil {
		t.Fatalf("read VEX: %v", err)
	}
	// Attached after the fact, and never signed.
	if _, err := security.AttachVEX(ctx, store, pushed.Manifest, []security.VEXDocument{{Name: "unsigned", Data: vexData}}); err != nil {
		t.Fatalf("AttachVEX: %v", err)
	}

	policy := signature.Policy{Verifier: key}
	hook := &pullScanHook{logger: logger, policy: policy, verify: signature.NewVerifier(plugin.Dir(baseDir), policy, logger)}
	v, err := hook.publisherVEX(ctx, store, hookTag, pushed.Manifest)
	if err != nil {
		t.Fatalf("publisherVEX: %v", err)
	}
	if v != nil {
		t.Errorf("publisherVEX = %+v, want the unsigned document ignored", v)
	}
}

func TestPushVEXFlagAcceptsStoredNames(t *testing.T) {
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
