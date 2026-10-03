package signature

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/testutil"
)

// TestCallsParseWithPkgPlugin makes every signing contract call bomify
// makes against a plugin built with pkg/plugin's builders (see
// testutil.InstallLibPlugin), so an argument they don't accept fails here
// rather than in a real plugin. The plugin answers from what it was given,
// which shows the files and flags arrived.
func TestCallsParseWithPkgPlugin(t *testing.T) {
	bin := testutil.InstallLibPlugin(t, t.TempDir(), "lib")
	logger := discardLogger()
	options := []string{"key=signing.key", "mode=test"}
	const ref = "registry.example.com/app:1"

	file := func(name, content string) string {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	payload := file("payload.json", "payload")
	statement := file("statement.json", "statement")
	envelope := file("envelope", "envelope")

	if result, err := signPayload(bin, payload, ref, options, logger); err != nil {
		t.Errorf("signPayload: %v", err)
	} else if string(result.Envelope) != "payload" {
		t.Errorf("signPayload envelope = %q, want the payload", result.Envelope)
	}
	if result, err := attestStatement(bin, statement, ref, options, logger); err != nil {
		t.Errorf("attestStatement: %v", err)
	} else if string(result.Envelope) != "statement" {
		t.Errorf("attestStatement envelope = %q, want the statement", result.Envelope)
	}
	if result, err := verifyEnvelope(bin, payload, envelope, "application/test", ref, options, logger); err != nil {
		t.Errorf("verifyEnvelope: %v", err)
	} else if result.Signer != ref {
		t.Errorf("verifyEnvelope signer = %q, want the reference %q", result.Signer, ref)
	}
	if result, err := verifyAttestationEnvelope(bin, envelope, "application/test", "sha256:"+fakeDigest, ref, options, logger); err != nil {
		t.Errorf("verifyAttestationEnvelope: %v", err)
	} else if string(result.Statement) != "envelope" {
		t.Errorf("verifyAttestationEnvelope statement = %q, want the envelope", result.Statement)
	}
	if supported, err := supportedTypes(bin, logger); err != nil {
		t.Errorf("supportedTypes: %v", err)
	} else if len(supported.ArtifactTypes) != 1 {
		t.Errorf("supportedTypes = %+v, want one type", supported)
	}
}

// fakeDigest is a well-formed SHA-256 hex digest.
const fakeDigest = "ae88ae88ae88ae88ae88ae88ae88ae88ae88ae88ae88ae88ae88ae88ae88ae88"
