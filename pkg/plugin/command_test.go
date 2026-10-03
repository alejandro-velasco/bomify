package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeComponent records the requests ComponentCommand hands it.
type fakeComponent struct {
	pull PullRequest
	push PushRequest
}

func (f *fakeComponent) Pull(_ context.Context, req PullRequest) (*Result, error) {
	f.pull = req
	if req.Logger == nil {
		return nil, errors.New("no logger")
	}
	return &Result{OutputPath: req.Output, Hash: NewHash("abc")}, nil
}

func (f *fakeComponent) Push(_ context.Context, req PushRequest) (*Result, error) {
	f.push = req
	return &Result{OutputPath: req.Remote + "/x"}, nil
}

func (f *fakeComponent) Remote(_ context.Context, purl string, _ *slog.Logger) (string, error) {
	return "origin-of-" + purl, nil
}

// runComponent executes the component command tree around p with args,
// returning its stdout.
func runComponent(t *testing.T, p ComponentPlugin, args ...string) (string, error) {
	t.Helper()
	root := NewRootCommand("fake", "fake", ComponentCommand(p, ComponentHelp{}))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs(append([]string{"component"}, args...))
	err := root.Execute()
	return out.String(), err
}

func TestComponentCommandPull(t *testing.T) {
	p := &fakeComponent{}
	log := filepath.Join(t.TempDir(), "log")

	out, err := runComponent(t, p, "pull", "--purl", "pkg:x/y?a=1&b=2", "--output", "dir", "--log", log)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if p.pull.Purl != "pkg:x/y?a=1&b=2" || p.pull.Output != "dir" || p.pull.Check {
		t.Errorf("request = %+v", p.pull)
	}

	var result Result
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("stdout %q is not one Result: %v", out, err)
	}
	if result.Hash != NewHash("abc") {
		t.Errorf("hash = %+v", result.Hash)
	}
}

func TestComponentCommandOutputRequiredUnlessCheck(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")

	if _, err := runComponent(t, &fakeComponent{}, "pull", "--purl", "p", "--log", log); err == nil || !strings.Contains(err.Error(), "output") {
		t.Errorf("pull without --output: err = %v, want it to name --output", err)
	}

	p := &fakeComponent{}
	if _, err := runComponent(t, p, "pull", "--purl", "p", "--check", "--log", log); err != nil {
		t.Fatalf("pull --check without --output: %v", err)
	}
	if !p.pull.Check {
		t.Error("Check not set")
	}
}

func TestComponentCommandPushRequiresRemote(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	if _, err := runComponent(t, &fakeComponent{}, "push", "--purl", "p", "--input", "in", "--log", log); err == nil {
		t.Error("push without --remote succeeded")
	}
}

func TestComponentCommandRemote(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	out, err := runComponent(t, &fakeComponent{}, "remote", "--purl", "p", "--log", log)
	if err != nil {
		t.Fatalf("remote: %v", err)
	}
	if strings.TrimSpace(out) != `{"remote":"origin-of-p"}` {
		t.Errorf("stdout = %q", out)
	}
}

func TestPrintKeepsPurlQueryIntact(t *testing.T) {
	var out bytes.Buffer
	if err := Print(&out, RemoteResult{Remote: "a?b=1&c=2"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "&c=2") {
		t.Errorf("Print HTML-escaped the result: %s", out.String())
	}
}

// fakeSigner records the requests SignatureCommand hands it.
type fakeSigner struct {
	sign        SignRequest
	attest      AttestRequest
	attestation VerifyAttestationRequest
}

func (f *fakeSigner) Sign(_ context.Context, req SignRequest) (SignResult, error) {
	f.sign = req
	return SignResult{ArtifactType: "a", MediaType: "m", Envelope: []byte("e")}, nil
}

func (f *fakeSigner) Attest(_ context.Context, req AttestRequest) (SignResult, error) {
	f.attest = req
	return SignResult{ArtifactType: "a", MediaType: "m", Envelope: []byte("e")}, nil
}

func (f *fakeSigner) Verify(context.Context, VerifyRequest) (VerifyResult, error) {
	return VerifyResult{}, nil
}

func (f *fakeSigner) VerifyAttestation(_ context.Context, req VerifyAttestationRequest) (VerifyAttestationResult, error) {
	f.attestation = req
	return VerifyAttestationResult{Signer: "s", Statement: []byte("statement")}, nil
}

func (f *fakeSigner) SupportedTypes(context.Context) (SupportedSignatureTypesResult, error) {
	return SupportedSignatureTypesResult{}, nil
}

func TestSignatureCommandAttest(t *testing.T) {
	statement := filepath.Join(t.TempDir(), "statement.json")
	if err := os.WriteFile(statement, []byte("statement"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &fakeSigner{}
	root := NewRootCommand("fake", "fake", SignatureCommand(p, SigningHelp{}))
	root.SetOut(&bytes.Buffer{})
	root.SetArgs([]string{"signature", "attest", "--statement", statement, "--reference", "app:1", "--option", "key=k"})
	if err := root.Execute(); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if string(p.attest.Statement) != "statement" || p.attest.Reference != "app:1" || len(p.attest.Options) != 1 {
		t.Errorf("request = %+v", p.attest)
	}
	if p.sign.Payload != nil {
		t.Error("attest called Sign")
	}
}

func TestSignatureCommandVerifyAttestation(t *testing.T) {
	envelope := filepath.Join(t.TempDir(), "envelope")
	if err := os.WriteFile(envelope, []byte("envelope"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &fakeSigner{}
	root := NewRootCommand("fake", "fake", SignatureCommand(p, SigningHelp{}))
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"signature", "verify-attestation", "--envelope", envelope, "--media-type", "m", "--subject", "sha256:ab", "--reference", "app:1"})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify-attestation: %v", err)
	}
	if string(p.attestation.Envelope) != "envelope" || p.attestation.MediaType != "m" || p.attestation.Subject != "sha256:ab" || p.attestation.Reference != "app:1" {
		t.Errorf("request = %+v", p.attestation)
	}
	if want := `{"signer":"s","statement":"c3RhdGVtZW50"}`; strings.TrimSpace(out.String()) != want {
		t.Errorf("stdout = %s, want %s", out.String(), want)
	}
}
