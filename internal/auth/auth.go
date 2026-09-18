// Package auth is bomify's single, shared source of registry credentials:
// a thin wrapper around the standard Docker config.json plus native OS
// credential store, the same files and stores `docker login`/`docker
// logout` read and write. cmd/push.go and cmd/pull.go use Client; plugins
// use Get (see HelperFunc to adapt it to a third-party SDK's own
// credential-helper interface).
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
// standard Docker config file, delegating to the platform's native
// credential helper exactly as `docker login` does. A bomify login is
// thus also a docker login, and vice versa.
func Store() (credentials.Store, error) {
	store, err := newStore()
	if err != nil {
		return nil, fmt.Errorf("open credential store: %w", err)
	}
	return store, nil
}

// newStore is Store's actual construction, factored out so tests can
// substitute an in-memory store instead of touching this machine's real
// native credential helper.
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

// Lookup returns whatever credentials are stored for host, or
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
// the "Get(serverURL string) (string, string, error)" shape several
// third-party credential-helper interfaces use, so plugins can hand it
// straight to whatever SDK they call (see HelperFunc).
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

// ErrNotFound is the docker-credential-helpers convention for "no
// credentials for this server", which adapters like
// authn.NewKeychainFromHelper check for to fall back to anonymous access.
// Get's own convention for the same case is empty strings with a nil
// error instead — without this translation, such an adapter would send
// Get's empty strings as a real (if blank) Basic credential and get
// rejected rather than falling back to anonymous.
var ErrNotFound = errors.New("credentials not found")

// HelperFunc adapts a Get-shaped function to the single-method
// "Get(serverURL string) (string, string, error)" interface several SDKs
// expect, translating "not found" into ErrNotFound (see ErrNotFound). For
// example, authn.NewKeychainFromHelper(auth.HelperFunc(auth.Get)) builds a
// go-containerregistry Keychain backed directly by this package.
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
	// file itself instead — the same fallback `docker login` makes when
	// no credsStore is configured.
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
		// Verification already succeeded; only the store step failed for
		// lack of a native credential helper. Fall back to plaintext, same
		// as `docker login`, under the same normalized hostname
		// credentials.Login itself would use so later lookups find it.
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
