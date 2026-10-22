package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// fakeComponent records the requests ComponentCommand hands it.
type fakeComponent struct {
	pull PullRequest
}

func (f *fakeComponent) Pull(_ context.Context, req PullRequest) (*Result, error) {
	f.pull = req
	if req.Logger == nil {
		return nil, errors.New("no logger")
	}
	return &Result{OutputPath: req.Output, Hash: NewHash("abc")}, nil
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

// fakeProgress reports pulling one 5-byte part through req.Progress.
type fakeProgress struct{}

func (fakeProgress) Pull(_ context.Context, req PullRequest) (*Result, error) {
	writer := req.Progress.Writer("part", 5)
	if _, err := writer.Write([]byte("bytes")); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return &Result{OutputPath: req.Output}, nil
}

func TestComponentCommandPullReportsProgress(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	progress := filepath.Join(dir, "progress")

	if _, err := runComponent(t, fakeProgress{}, "pull", "--purl", "p", "--output", "out", "--log", log, "--progress", progress); err != nil {
		t.Fatalf("pull: %v", err)
	}

	data, err := os.ReadFile(progress)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"part","current":0,"total":5}` + "\n" + `{"name":"part","current":5,"total":5}` + "\n"
	if string(data) != want {
		t.Errorf("progress file = %q, want %q", data, want)
	}
}

func TestComponentCommandPullWithoutProgress(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")

	// --check passes no --progress, and the plugin reports anyway.
	if _, err := runComponent(t, fakeProgress{}, "pull", "--purl", "p", "--check", "--log", log); err != nil {
		t.Fatalf("pull --check: %v", err)
	}
}

// fakePacker is a fakeComponent that packs, recording the request.
type fakePacker struct {
	fakeComponent
	pack PackRequest
}

func (f *fakePacker) Pack(_ context.Context, req PackRequest) (*PackResult, error) {
	f.pack = req
	manifest := InlineBlob("application/vnd.oci.image.manifest.v1+json", []byte("{}"))
	return &PackResult{Manifest: &manifest}, nil
}

func TestComponentCommandPackWithoutAFormat(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	out, err := runComponent(t, &fakeComponent{}, "pack", "--purl", "p", "--input", "in", "--log", log)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if strings.TrimSpace(out) != "{}" {
		t.Errorf("stdout = %q, want {}", out)
	}
}

func TestComponentCommandPack(t *testing.T) {
	p := &fakePacker{}
	log := filepath.Join(t.TempDir(), "log")
	out, err := runComponent(t, p, "pack", "--purl", "p", "--input", "in", "--log", log)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if p.pack.Purl != "p" || p.pack.Input != "in" || p.pack.Logger == nil {
		t.Errorf("request = %+v", p.pack)
	}
	var result PackResult
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.Manifest == nil || string(result.Manifest.Data) != "{}" {
		t.Errorf("stdout = %q, %v; want the PackResult", out, err)
	}
}

func TestComponentCommandPackRequiresInput(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	if _, err := runComponent(t, &fakePacker{}, "pack", "--purl", "p", "--log", log); err == nil {
		t.Error("pack without --input succeeded")
	}
}

// TestInlineBlob pins an inline blob's descriptor to its data, and its
// JSON to base64, as the contract has it.
func TestInlineBlob(t *testing.T) {
	blob := InlineBlob("application/json", []byte("{}"))
	want := "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if blob.Digest != want || blob.Size != 2 || blob.Path != "" {
		t.Errorf("InlineBlob = %+v, want digest %s, size 2, no path", blob, want)
	}
	data, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"data":"e30="`) || strings.Contains(string(data), `"path"`) {
		t.Errorf("JSON = %s, want the data in base64, and no path", data)
	}
}

func TestPrintKeepsPurlQueryIntact(t *testing.T) {
	var out bytes.Buffer
	if err := Print(&out, Result{OutputPath: "a?b=1&c=2"}); err != nil {
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

// fakeScanner is a SecurityPlugin that's never called.
type fakeScanner struct{}

func (fakeScanner) Scan(context.Context, string) (SecurityResult, error) {
	return SecurityResult{}, nil
}

func (fakeScanner) SupportedComponents(context.Context) (SupportedComponentsResult, error) {
	return SupportedComponentsResult{}, nil
}

func TestContractCommand(t *testing.T) {
	for name, tc := range map[string]struct {
		contracts []*cobra.Command
		want      string
	}{
		"every contract": {
			[]*cobra.Command{
				ComponentCommand(&fakeComponent{}, ComponentHelp{}),
				// SBOM generation has no builder: a plugin's own "sbom"
				// command counts.
				{Use: "sbom"},
				SecurityCommand(fakeScanner{}, SecurityHelp{}),
				SignatureCommand(&fakeSigner{}, SigningHelp{}),
				// Neither does a command of no contract.
				{Use: "other"},
			},
			`{"contracts":{"component":1,"sbom":1,"security":1,"signing":1}}`,
		},
		"one contract": {
			[]*cobra.Command{SignatureCommand(&fakeSigner{}, SigningHelp{})},
			`{"contracts":{"signing":1}}`,
		},
		"none": {nil, `{"contracts":{}}`},
	} {
		root := NewRootCommand("fake", "fake", tc.contracts...)
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"contract"})
		if err := root.Execute(); err != nil {
			t.Errorf("%s: contract: %v", name, err)
			continue
		}
		if got := strings.TrimSpace(out.String()); got != tc.want {
			t.Errorf("%s: stdout = %s, want %s", name, got, tc.want)
		}
	}
}
