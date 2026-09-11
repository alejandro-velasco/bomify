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
	"errors"
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

// newPlaintextStore is Login's fallback when no native credential helper
// is available: the same config file, but willing to write a credential
// into it as plaintext rather than refusing. Factored out for the same
// test-isolation reason as newStore.
var newPlaintextStore = func() (credentials.Store, error) {
	return credentials.NewStoreFromDocker(credentials.StoreOptions{
		AllowPlaintextPut: true,
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

	credentialFn := credentials.Credential(store)
	return credentialFn(ctx, host)
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

// ErrNotFound signals "no credentials for this server" through a
// single-method Helper interface — the convention docker-credential-helpers
// (and adapters built on it, like go-containerregistry's
// authn.NewKeychainFromHelper) actually use to fall back to anonymous
// access. It's distinct from Get's own convention for the same situation
// (empty username/password, nil error): a Helper-consuming adapter that
// only checks for a non-nil error — as authn.NewKeychainFromHelper does —
// would otherwise treat Get's empty strings as a real (if blank) Basic
// credential, and have the registry reject the request as a bad login
// instead of an anonymous one.
var ErrNotFound = errors.New("credentials not found")

// HelperFunc adapts a function shaped like Get into any single-method
// "Get(serverURL string) (string, string, error)" interface, translating
// "not found" into ErrNotFound as it does — see ErrNotFound for why that
// translation matters. For example,
// authn.NewKeychainFromHelper(auth.HelperFunc(auth.Get)) builds a
// go-containerregistry Keychain backed directly by this package, without
// go-containerregistry's authn package needing to know bomify exists.
type HelperFunc func(serverURL string) (string, string, error)

// Get implements the single-method Helper shape HelperFunc adapts to.
func (f HelperFunc) Get(serverURL string) (string, string, error) {
	username, password, err := f(serverURL)
	if err == nil && username == "" && password == "" {
		return "", "", ErrNotFound
	}
	return username, password, err
}

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

// LoginResult reports how Login stored a successfully verified
// credential.
type LoginResult struct {
	// PlaintextFallback is true when no native credential helper was
	// available, so the credential was stored as plaintext in the config
	// file itself instead — the same fallback (with the same "this isn't
	// encrypted" caveat) `docker login` falls back to when no credsStore
	// is configured.
	PlaintextFallback bool
}

// Login verifies username/password against host and, only if they work,
// stores them — the same real-login-then-save behavior `docker login`
// performs, so a mistyped password is caught immediately rather than
// saved and only discovered on the next push/pull.
func Login(ctx context.Context, host, username, password string) (LoginResult, error) {
	reg, err := remote.NewRegistry(host)
	if err != nil {
		return LoginResult{}, fmt.Errorf("invalid registry %q: %w", host, err)
	}
	return loginToRegistry(ctx, reg, username, password)
}

// loginToRegistry does the actual verify-then-save Login performs,
// against an already-constructed *remote.Registry — factored out of
// Login so tests can point it at a local, plain-HTTP fake registry
// without Login itself growing a test-only way to disable TLS.
func loginToRegistry(ctx context.Context, reg *remote.Registry, username, password string) (LoginResult, error) {
	store, err := Store()
	if err != nil {
		return LoginResult{}, err
	}

	cred := orasauth.Credential{Username: username, Password: password}

	err = credentials.Login(ctx, store, reg, cred)
	if errors.Is(err, credentials.ErrPlaintextPutDisabled) {
		// credentials.Login already verified username/password against
		// the registry successfully — only the store step failed, because
		// no native credential helper is available here. Save as
		// plaintext instead of blocking the login outright, exactly as
		// `docker login` itself falls back.
		// Store under the same normalized hostname credentials.Login
		// itself would have used (e.g. "docker.io" maps to
		// "https://index.docker.io/v1/"), so this fallback is found by
		// the exact same lookups a successful Login's write would be.
		hostname := credentials.ServerAddressFromRegistry(reg.Reference.Registry)

		plainStore, perr := newPlaintextStore()
		if perr != nil {
			return LoginResult{}, perr
		}
		if perr := plainStore.Put(ctx, hostname, cred); perr != nil {
			return LoginResult{}, fmt.Errorf("login to %s: store plaintext credentials: %w", hostname, perr)
		}
		return LoginResult{PlaintextFallback: true}, nil
	}
	if err != nil {
		return LoginResult{}, fmt.Errorf("login to %s: %w", reg.Reference.Registry, err)
	}

	return LoginResult{}, nil
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
