package hub

import (
	"os"
	"path/filepath"
	"testing"
)

// useCredentials makes lookupCredentials report token for host only, and
// records which hosts were looked up.
func useCredentials(t *testing.T, host, token string) *[]string {
	t.Helper()
	var looked []string
	original := lookupCredentials
	lookupCredentials = func(lookedUp string) (string, string, error) {
		looked = append(looked, lookedUp)
		if lookedUp == host {
			return "user", token, nil
		}
		return "", "", nil
	}
	t.Cleanup(func() { lookupCredentials = original })
	return &looked
}

// isolateTokens clears every place Token looks, so a test sees only what
// it sets up.
func isolateTokens(t *testing.T) {
	t.Helper()
	t.Setenv("HF_TOKEN", "")
	t.Setenv("HF_ENDPOINT", "")
	t.Setenv("HF_TOKEN_PATH", filepath.Join(t.TempDir(), "no-token"))
}

func TestTokenPrefersHFToken(t *testing.T) {
	isolateTokens(t)
	t.Setenv("HF_TOKEN", "hf_env")
	looked := useCredentials(t, DefaultHost, "hf_stored")

	if token, err := Token("", discardLogger()); err != nil || token != "hf_env" {
		t.Errorf("Token = %q, %v; want $HF_TOKEN's", token, err)
	}
	if len(*looked) != 0 {
		t.Errorf("looked up %v, want nothing", *looked)
	}
}

func TestTokenUsesBomifyLoginForTheHubsHost(t *testing.T) {
	isolateTokens(t)
	looked := useCredentials(t, DefaultHost, "hf_stored")

	if token, err := Token("", discardLogger()); err != nil || token != "hf_stored" {
		t.Errorf("Token(default hub) = %q, %v; want hf_stored", token, err)
	}
	if token, err := Token("https://hub.example.com/mirror", discardLogger()); err != nil || token != "" {
		t.Errorf("Token(other hub) = %q, %v; want none", token, err)
	}
	if len(*looked) != 2 || (*looked)[0] != DefaultHost || (*looked)[1] != "hub.example.com" {
		t.Errorf("looked up %v, want [%s hub.example.com]", *looked, DefaultHost)
	}
}

func TestTokenFollowsHFEndpoint(t *testing.T) {
	isolateTokens(t)
	t.Setenv("HF_ENDPOINT", "https://mirror.example.com")
	useCredentials(t, "mirror.example.com", "hf_mirror")

	if token, err := Token("", discardLogger()); err != nil || token != "hf_mirror" {
		t.Errorf("Token = %q, %v; want the mirror's", token, err)
	}
}

func TestTokenFallsBackToHFLogin(t *testing.T) {
	isolateTokens(t)
	useCredentials(t, "", "")
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("hf_login\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HF_TOKEN_PATH", path)

	if token, err := Token("", discardLogger()); err != nil || token != "hf_login" {
		t.Errorf("Token = %q, %v; want hf auth login's", token, err)
	}
}

func TestTokenNone(t *testing.T) {
	isolateTokens(t)
	useCredentials(t, "", "")

	if token, err := Token("", discardLogger()); err != nil || token != "" {
		t.Errorf("Token = %q, %v; want none", token, err)
	}
}
