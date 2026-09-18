package auth

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
)

func TestCredentialToUserPassPrefersUsernamePassword(t *testing.T) {
	username, password := credentialToUserPass(orasauth.Credential{Username: "alice", Password: "s3cret"})
	if username != "alice" || password != "s3cret" {
		t.Errorf("credentialToUserPass() = (%q, %q), want (\"alice\", \"s3cret\")", username, password)
	}
}

func TestCredentialToUserPassFallsBackToRefreshToken(t *testing.T) {
	username, password := credentialToUserPass(orasauth.Credential{RefreshToken: "a-refresh-token"})
	if username != "" || password != "a-refresh-token" {
		t.Errorf("credentialToUserPass() = (%q, %q), want (\"\", \"a-refresh-token\")", username, password)
	}
}

func TestCredentialToUserPassFallsBackToAccessToken(t *testing.T) {
	username, password := credentialToUserPass(orasauth.Credential{AccessToken: "an-access-token"})
	if username != "" || password != "an-access-token" {
		t.Errorf("credentialToUserPass() = (%q, %q), want (\"\", \"an-access-token\")", username, password)
	}
}

func TestCredentialToUserPassEmptyWhenNothingStored(t *testing.T) {
	username, password := credentialToUserPass(orasauth.EmptyCredential)
	if username != "" || password != "" {
		t.Errorf("credentialToUserPass() = (%q, %q), want (\"\", \"\")", username, password)
	}
}

func TestHelperFuncAdaptsGet(t *testing.T) {
	var helper interface {
		Get(serverURL string) (string, string, error)
	} = HelperFunc(func(serverURL string) (string, string, error) {
		return "alice", "s3cret", nil
	})

	username, password, err := helper.Get("example.com")
	if err != nil {
		t.Fatalf("helper.Get() error = %v", err)
	}
	if username != "alice" || password != "s3cret" {
		t.Errorf("helper.Get() = (%q, %q), want (\"alice\", \"s3cret\")", username, password)
	}
}

type fakeResource string

func (r fakeResource) String() string      { return string(r) }
func (r fakeResource) RegistryStr() string { return string(r) }

// TestHelperFuncSignalsAnonymousToRealKeychainAdapter reproduces a real
// bug: fed through go-containerregistry's own
// authn.NewKeychainFromHelper — used by bomify-plugin-oci to authenticate
// crane's pull/push — a host with nothing stored used to resolve to a
// real (if blank) Basic authenticator rather than anonymous access,
// because that adapter only falls back to Anonymous on a non-nil error,
// not on empty username/password. A registry then rejected that blank
// Basic credential as a bad login, turning what should have been an
// always-succeeding anonymous pull of a public image into a guaranteed
// failure. This exercises the real go-containerregistry adapter, not
// just HelperFunc.Get's return values, so it fails the same way the
// original bug did if the fix regresses.
func TestHelperFuncSignalsAnonymousToRealKeychainAdapter(t *testing.T) {
	kc := authn.NewKeychainFromHelper(HelperFunc(func(string) (string, string, error) {
		return "", "", nil // nothing stored for this host
	}))

	authenticator, err := kc.Resolve(fakeResource("example.com"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if authenticator != authn.Anonymous {
		t.Errorf("Resolve() = %#v, want authn.Anonymous", authenticator)
	}
}

func TestHelperFuncSignalsRealCredentialToKeychainAdapter(t *testing.T) {
	kc := authn.NewKeychainFromHelper(HelperFunc(func(string) (string, string, error) {
		return "alice", "s3cret", nil
	}))

	authenticator, err := kc.Resolve(fakeResource("example.com"))
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	cfg, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization() error = %v", err)
	}
	if cfg.Username != "alice" || cfg.Password != "s3cret" {
		t.Errorf("Authorization() = %+v, want Username=alice Password=s3cret", cfg)
	}
}
