package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// signingDataDir is a fresh data directory with only the fake signing
// plugin, as a co-signer's environment would be: no packages, and no
// other signer's key.
func signingDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	testutil.InstallFakePlugin(t, layout.Plugins(dir), "fakesign")
	return dir
}

// releaseSigned saves buildApp's package signed only by the release key
// and returns the tarball.
func releaseSigned(t *testing.T) string {
	t.Helper()
	baseDir, _ := buildApp(t)
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", "app:1.0", "--output", archive, "--sign", "fakesign", "--sign-option", "key=release"); err != nil {
		t.Fatalf("save: %v", err)
	}
	return archive
}

// TestSignCosignsFromAnotherEnvironment signs a package in two separate
// data directories, each with only its own key, and loads it under a rule
// requiring both.
func TestSignCosignsFromAnotherEnvironment(t *testing.T) {
	archive := releaseSigned(t)

	destDir, err := loadUnderRules(t, archive, trusts("release"), trusts("security"))
	if err == nil {
		t.Fatal("load with only the release signature: nil, want error")
	}
	requireNothingRestored(t, destDir)

	security := signingDataDir(t)
	if _, err := runRootCmd(t, security, "signer", "create", "security", "fakesign", "--option", "key=security"); err != nil {
		t.Fatal(err)
	}
	if _, err := runRootCmd(t, security, "sign", "--input", archive, "--signer", "security"); err != nil {
		t.Fatalf("sign --input (in place): %v", err)
	}

	if _, err := loadUnderRules(t, archive, trusts("release"), trusts("security")); err != nil {
		t.Errorf("load signed by both: %v", err)
	}
}

func TestSignOutputLeavesInputAlone(t *testing.T) {
	archive := releaseSigned(t)
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}

	signed := filepath.Join(t.TempDir(), "signed.tar")
	if _, err := runRootCmd(t, signingDataDir(t), "sign", "--input", archive, "--output", signed, "--sign", "fakesign", "--sign-option", "key=security"); err != nil {
		t.Fatalf("sign --output: %v", err)
	}

	if after, _ := os.ReadFile(archive); string(after) != string(before) {
		t.Error("sign --output changed --input")
	}
	if _, err := loadUnderRules(t, signed, trusts("release"), trusts("security")); err != nil {
		t.Errorf("load of --output signed by both: %v", err)
	}
}

func TestSignArgs(t *testing.T) {
	baseDir := signingDataDir(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"nothing to sign", []string{"sign", "--sign", "fakesign"}, "give a <reference>, or --input"},
		{"both", []string{"sign", "reg/app:1.0", "--input", "x.tar", "--sign", "fakesign"}, "not both"},
		{"output without input", []string{"sign", "reg/app:1.0", "--output", "x.tar", "--sign", "fakesign"}, "--output needs --input"},
		{"no signer", []string{"sign", "reg/app:1.0"}, "nothing to sign with"},
		{"missing input", []string{"sign", "--input", filepath.Join(t.TempDir(), "missing.tar"), "--sign", "fakesign"}, "missing.tar"},
	} {
		_, err := runRootCmd(t, baseDir, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want one containing %q", tc.name, err, tc.want)
		}
	}
}
