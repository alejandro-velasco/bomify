package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// savedCosigned saves buildApp's package signed as each of signers, a
// stored fakesign signer with key=<name>, and returns the tarball.
func savedCosigned(t *testing.T, signers []string, flags ...string) string {
	t.Helper()
	baseDir, _ := buildApp(t, flags...)
	args := []string{"save", "app:1.0", "--output", filepath.Join(t.TempDir(), "app.tar")}
	for _, name := range signers {
		if _, err := runRootCmd(t, baseDir, "signer", "create", name, "fakesign", "--option", "key="+name); err != nil {
			t.Fatalf("signer create %s: %v", name, err)
		}
		args = append(args, "--signer", name)
	}
	if _, err := runRootCmd(t, baseDir, args...); err != nil {
		t.Fatalf("save %v: %v", args, err)
	}
	return args[3]
}

// loadUnderRules loads archive into a fresh data directory with fakesign
// installed, after running each of rules there.
func loadUnderRules(t *testing.T, archive string, rules ...[]string) (string, error) {
	t.Helper()
	destDir := t.TempDir()
	testutil.InstallFakePlugin(t, layout.Plugins(destDir), "fakesign")
	for _, rule := range rules {
		if _, err := runRootCmd(t, destDir, rule...); err != nil {
			t.Fatalf("%v: %v", rule, err)
		}
	}
	_, err := runRootCmd(t, destDir, "load", "--input", archive)
	return destDir, err
}

// trusts is a "bomify trust create" requiring a fakesign signature by the
// signer called name, with key=<name>, plus flags.
func trusts(name string, flags ...string) []string {
	return append([]string{"trust", "create", "fakesign", "--signer", name, "--option", "key=" + name}, flags...)
}

func TestLoadRequiresEverySigner(t *testing.T) {
	both := savedCosigned(t, []string{"release", "security"})

	if _, err := loadUnderRules(t, both, trusts("release"), trusts("security")); err != nil {
		t.Errorf("load signed by both required signers: %v", err)
	}

	destDir, err := loadUnderRules(t, savedCosigned(t, []string{"release"}), trusts("release"), trusts("security"))
	if err == nil || !strings.Contains(err.Error(), `signer "security"`) {
		t.Errorf("load missing a required signer: %v, want an error naming it", err)
	}
	requireNothingRestored(t, destDir)
}

// TestSignAndSignerTogether signs one save with a plugin given by --sign
// and a stored --signer, which together meet a rule requiring both.
func TestSignAndSignerTogether(t *testing.T) {
	baseDir, _ := buildApp(t)
	if _, err := runRootCmd(t, baseDir, "signer", "create", "security", "fakesign", "--option", "key=security"); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "app.tar")
	if _, err := runRootCmd(t, baseDir, "save", "app:1.0", "--output", archive, "--sign", "fakesign", "--sign-option", "key=release", "--signer", "security"); err != nil {
		t.Fatalf("save --sign --signer: %v", err)
	}
	if _, err := loadUnderRules(t, archive, trusts("release"), trusts("security")); err != nil {
		t.Errorf("load requiring both: %v", err)
	}
}

func TestLoadRequiresSomeSigners(t *testing.T) {
	both := savedCosigned(t, []string{"alice", "bob"})

	destDir, err := loadUnderRules(t, both, trusts("alice"), trusts("bob"), trusts("carol"))
	if err == nil || !strings.Contains(err.Error(), "2 of the 3 required") {
		t.Errorf("load short of all three: %v, want an error", err)
	}
	requireNothingRestored(t, destDir)

	if _, err := loadUnderRules(t, both, trusts("alice"), trusts("bob"), trusts("carol", "--require", "2")); err != nil {
		t.Errorf("load with two of three, requiring 2: %v", err)
	}
	if _, err := loadUnderRules(t, savedCosigned(t, []string{"carol"}), trusts("alice"), trusts("bob"), trusts("carol", "--require", "2")); err == nil {
		t.Error("load with one of three, requiring 2: nil, want error")
	}
}

// TestCosignedProvenance checks that one trusted attestation is enough:
// a rule requiring provenance accepts it from whichever of its signers
// attested it.
func TestCosignedProvenance(t *testing.T) {
	// carol, tried first, didn't attest it; security did.
	archive := savedCosigned(t, []string{"security"}, "--provenance")
	if _, err := loadUnderRules(t, archive, trusts("carol"), trusts("security", "--require", "1", "--require-provenance")); err != nil {
		t.Errorf("load requiring provenance one signer attested: %v", err)
	}
}

func TestTrustSigners(t *testing.T) {
	baseDir := t.TempDir()
	run := func(args ...string) (string, error) {
		t.Helper()
		return runRootCmd(t, baseDir, args...)
	}

	for _, name := range []string{"release", "security"} {
		if _, err := run(trusts(name, "--match", "registry.example.com/prod")...); err != nil {
			t.Fatalf("trust create --signer %s: %v", name, err)
		}
	}
	if _, err := run(trusts("audit", "--match", "registry.example.com/prod", "--require", "2")...); err != nil {
		t.Fatalf("trust create --require 2: %v", err)
	}
	if _, err := run(trusts("x", "--require", "none")...); err == nil {
		t.Error("trust create --require none: nil, want error")
	}
	if _, err := run(trusts("x", "--match", "other", "--require", "2")...); err == nil {
		t.Error("trust create --require 2 for a one-signer rule: nil, want error")
	}

	out, err := run("trust", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SIGNER", "REQUIRE", "release", "security", "audit", "2 of 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("trust list output missing %q:\n%s", want, out)
		}
	}

	if _, err := run("trust", "remove", "--match", "registry.example.com/prod", "--signer", "audit"); err != nil {
		t.Fatalf("trust remove --signer: %v", err)
	}
	if _, err := run("trust", "remove", "--match", "registry.example.com/prod", "--signer", "security"); err == nil {
		t.Error("trust remove --signer below --require: nil, want error")
	}
	if out, _ := run("trust", "list"); strings.Contains(out, "audit") || !strings.Contains(out, "security") {
		t.Errorf("trust list after removing a signer:\n%s", out)
	}
}

func TestTrustUnnamedSigner(t *testing.T) {
	baseDir := t.TempDir()
	if _, err := runRootCmd(t, baseDir, "trust", "create", "sigstore", "--match", "m", "--option", "key=org.pub"); err != nil {
		t.Fatal(err)
	}
	if _, err := runRootCmd(t, baseDir, trusts("security", "--match", "m")...); err != nil {
		t.Fatal(err)
	}
	out, err := runRootCmd(t, baseDir, "trust", "list")
	if err != nil || !strings.Contains(out, " - ") || !strings.Contains(out, "security") {
		t.Errorf("trust list = %q, %v; want the unnamed signer as - beside security", out, err)
	}

	if _, err := runRootCmd(t, baseDir, "trust", "remove", "--match", "m", "--signer", ""); err != nil {
		t.Fatalf("trust remove --signer '': %v", err)
	}
	if out, _ := runRootCmd(t, baseDir, "trust", "list"); strings.Contains(out, "key=org.pub") {
		t.Errorf("unnamed signer still listed:\n%s", out)
	}
}

func TestSignerCreateListRemove(t *testing.T) {
	baseDir := t.TempDir()
	if _, err := runRootCmd(t, baseDir, "signer", "create", "release", "sigstore", "--option", "key=release.key"); err != nil {
		t.Fatalf("signer create: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "signer", "create", "bad", "sigstore", "--option", "key="); err == nil {
		t.Error("signer create with an empty option value: nil, want error")
	}

	out, err := runRootCmd(t, baseDir, "signer", "list")
	if err != nil || !strings.Contains(out, "release") || !strings.Contains(out, "key=release.key") {
		t.Errorf("signer list = %q, %v; want the signer and its options", out, err)
	}

	if _, err := runRootCmd(t, baseDir, "signer", "remove", "release"); err != nil {
		t.Fatalf("signer remove: %v", err)
	}
	if _, err := runRootCmd(t, baseDir, "signer", "remove", "release"); err == nil {
		t.Error("signer remove of a missing signer: nil, want error")
	}
}

func TestSignFlagValidation(t *testing.T) {
	baseDir := t.TempDir()
	if _, err := runRootCmd(t, baseDir, "signer", "create", "release", "sigstore", "--option", "key=release.key"); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"same signer twice", []string{"--signer", "release", "--signer", "release"}, "more than once"},
		{"unknown signer", []string{"--signer", "relase"}, `--signer "relase": no such signer`},
		{"options without a plugin", []string{"--signer", "release", "--sign-option", "key=a"}, "without --sign"},
	} {
		_, err := runRootCmd(t, baseDir, append([]string{"save", "app:v1"}, tt.args...)...)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v, want one containing %q", tt.name, err, tt.want)
		}
	}
}
