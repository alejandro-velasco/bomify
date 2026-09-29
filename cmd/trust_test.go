package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// runRootCmd runs bomify with args against baseDir, returning its stdout
// and error.
func runRootCmd(t *testing.T, baseDir string, args ...string) (string, error) {
	t.Helper()

	origDataDir := dataDir
	t.Cleanup(func() { dataDir = origDataDir })
	dataDir = ""

	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"--data-dir", baseDir}, args...))

	err = root.Execute()
	return stdout.String(), err
}

func TestTrustCreateListRemove(t *testing.T) {
	baseDir := t.TempDir()

	if _, err := runRootCmd(t, baseDir, "trust", "create", "sigstore", "--match", "registry.example.com/team", "--option", "key=team.pub"); err != nil {
		t.Fatalf("trust create: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "trust", "create", "notation"); err != nil {
		t.Fatalf("trust create (catch-all): %v", err)
	}

	out, err := runRootCmd(t, baseDir, "trust", "list")
	if err != nil {
		t.Fatalf("trust list: %v", err)
	}
	for _, want := range []string{"registry.example.com/team", "sigstore", "key=team.pub", "*", "notation"} {
		if !strings.Contains(out, want) {
			t.Errorf("trust list output missing %q:\n%s", want, out)
		}
	}

	if _, err := runRootCmd(t, baseDir, "trust", "remove", "--match", "registry.example.com/team"); err != nil {
		t.Fatalf("trust remove: %v", err)
	}
	if out, _ := runRootCmd(t, baseDir, "trust", "list"); strings.Contains(out, "sigstore") {
		t.Errorf("removed rule still listed:\n%s", out)
	}
}

func TestTrustCreateRejectsMalformedOption(t *testing.T) {
	if _, err := runRootCmd(t, t.TempDir(), "trust", "create", "sigstore", "--option", "novalue"); err == nil {
		t.Fatal("trust create with a non key=value --option: nil, want error")
	}
}

// TestTrustCreateRejectsEmptyOptionValue covers the classic unset shell
// variable ("certificate-identity=$ME"): the rule must be refused on the
// spot, not saved to fail every later pull.
func TestTrustCreateRejectsEmptyOptionValue(t *testing.T) {
	baseDir := t.TempDir()

	_, err := runRootCmd(t, baseDir, "trust", "create", "sigstore", "--match", "localhost/plugins", "--option", "certificate-identity=")
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("trust create with an empty --option value: %v, want an empty value error", err)
	}
	if out, _ := runRootCmd(t, baseDir, "trust", "list"); strings.Contains(out, "localhost/plugins") {
		t.Errorf("rule saved despite the error:\n%s", out)
	}
}

func TestSigningFlagValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"verify and skip", []string{"pull", "registry.example.com/app:v1", "--verify", "sigstore", "--insecure-skip-verify"}, "none of the others"},
		{"verify option without verify", []string{"pull", "registry.example.com/app:v1", "--verify-option", "key=a"}, "without --verify"},
		{"malformed verify option", []string{"load", "--verify", "sigstore", "--verify-option", "=a"}, "want key=value"},
		{"empty verify option value", []string{"load", "--verify", "sigstore", "--verify-option", "key="}, "empty value"},
		{"sign option without sign", []string{"save", "app:v1", "--sign-option", "key=a"}, "without --sign"},
		{"empty sign option value", []string{"save", "app:v1", "--sign", "sigstore", "--sign-option", "key="}, "empty value"},
		{"empty plugin install verify option value", []string{"plugin", "install", "oci", "--verify-option", "certificate-identity="}, "empty value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runRootCmd(t, t.TempDir(), tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}
