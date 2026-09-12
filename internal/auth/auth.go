// Package auth is bomify's single, shared source of registry credentials
// for both the main binary and its plugins: a thin wrapper around the
// standard Docker config.json plus native OS credential store (Windows
// Credential Manager, macOS Keychain, or a configured Linux helper) — the
// exact files and stores `docker login`/`docker logout` themselves read
// and write, via oras-go's credentials package, which in turn talks to
// that native store through github.com/docker/docker-credential-helpers.
//
// Every registry-talking piece of bomify goes through this package rather
// than re-deriving its own notion of where credentials live: cmd/push.go
// and cmd/pull.go via Client, and each plugin via Get (see HelperFunc for
// adapting it to a third-party SDK's own credential-helper interface).
package auth

import (
	"context"
	"fmt"

	"oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// DefaultHost is the registry Login/Logout (and the `bomify
// login`/`bomify logout` commands built on them) target when none is
// given, matching `docker login`'s own default.
const DefaultHost = "docker.io"

// Store returns the credential store bomify reads and writes: the
// standard Docker config file ($DOCKER_CONFIG/config.json, or
// $HOME/.docker/config.json if that's unset), delegating to the
// platform's native credential helper when the config file names one
// (auto-detecting and recording the platform default the first time a
// credential is stored, if none is configured yet), exactly as `docker
// login` does. A bomify login is thus also a docker login, and vice
// versa: both read and write the same store.
func Store() (credentials.Store, error) {
	store, err := newStore()
	if err != nil {
		return nil, fmt.Errorf("open credential store: %w", err)
	}
	return store, nil
}

// newStore is Store's actual construction, factored out so tests can
// substitute an in-memory store — Store's real implementation would
// otherwise auto-detect and configure this machine's actual native
// credential helper (Windows Credential Manager, macOS Keychain, ...) the
// first time a test writes a credential, polluting real, shared,
// system-wide state well outside any temp directory a test controls.
var newStore = func() (credentials.Store, error) {
	return credentials.NewStoreFromDocker(credentials.StoreOptions{
		DetectDefaultNativeStore: true,
	})
}

// Lookup returns whatever credentials are stored for host (a registry
// hostname, e.g. "registry-1.docker.io" or "localhost:5000"), or
// orasauth.EmptyCredential — not an error — if none are stored, so an
// anonymous pull/push against a public registry is never blocked by a
// missing login.
func Lookup(ctx context.Context, host string) (orasauth.Credential, error) {
	store, err := Store()
	if err != nil {
		return orasauth.EmptyCredential, err
	}
	return credentials.Credential(store)(ctx, host)
}

// Get returns just the username and secret stored for serverURL, or two
// empty strings if none are stored. Its signature deliberately matches
// the single-method "Get(serverURL string) (string, string, error)"
// shape both docker-credential-helpers' and go-containerregistry's own
// credential-helper interfaces use, so a plugin that needs to hand
// bomify's credentials to a third-party SDK expecting one of those can do
// so via HelperFunc without any bomify-specific glue inside that SDK.
func Get(serverURL string) (string, string, error) {
	cred, err := Lookup(context.Background(), serverURL)
	if err != nil {
		return "", "", err
	}

	if cred.Username != "" {
		return cred.Username, cred.Password, nil
	}

	// A registry using token-based auth (no username) still has a real
	// secret worth handing over.
	switch {
	case cred.RefreshToken != "":
		return "", cred.RefreshToken, nil
	case cred.AccessToken != "":
		return "", cred.AccessToken, nil
	default:
		return "", "", nil
	}
}

// HelperFunc adapts a function shaped like Get into any single-method
// "Get(serverURL string) (string, string, error)" interface. For
// example, authn.NewKeychainFromHelper(auth.HelperFunc(auth.Get)) builds
// a go-containerregistry Keychain backed directly by this package,
// without go-containerregistry's authn package needing to know bomify
// exists.
type HelperFunc func(serverURL string) (string, string, error)

// Get implements the single-method Helper shape HelperFunc adapts to.
func (f HelperFunc) Get(serverURL string) (string, string, error) { return f(serverURL) }

// Client returns an oras-go auth.Client backed by the shared store, ready
// to attach to a remote.Repository or remote.Registry (see
// remote.Repository.Client).
func Client() (*orasauth.Client, error) {
	store, err := Store()
	if err != nil {
		return nil, err
	}

	return &orasauth.Client{
		Cache:      orasauth.NewCache(),
		Credential: credentials.Credential(store),
	}, nil
}

// Login verifies username/password against host and, only if they work,
// stores them — the same real-login-then-save behavior `docker login`
// performs, so a mistyped password is caught immediately rather than
// saved and only discovered on the next push/pull.
func Login(ctx context.Context, host, username, password string) error {
	reg, err := remote.NewRegistry(host)
	if err != nil {
		return fmt.Errorf("invalid registry %q: %w", host, err)
	}
	return loginToRegistry(ctx, reg, username, password)
}

// loginToRegistry does the actual verify-then-save Login performs,
// against an already-constructed *remote.Registry — factored out of
// Login so tests can point it at a local, plain-HTTP fake registry
// without Login itself growing a test-only way to disable TLS.
func loginToRegistry(ctx context.Context, reg *remote.Registry, username, password string) error {
	store, err := Store()
	if err != nil {
		return err
	}

	cred := orasauth.Credential{Username: username, Password: password}
	if err := credentials.Login(ctx, store, reg, cred); err != nil {
		return fmt.Errorf("login to %s: %w", reg.Reference.Registry, err)
	}

	return nil
}

// Logout removes any stored credentials for host.
func Logout(ctx context.Context, host string) error {
	store, err := Store()
	if err != nil {
		return err
	}

	if err := credentials.Logout(ctx, store, host); err != nil {
		return fmt.Errorf("logout from %s: %w", host, err)
	}

	return nil
}
