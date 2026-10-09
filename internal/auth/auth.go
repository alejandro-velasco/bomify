// Package auth is bomify's single, shared source of registry credentials
// (see Store). cmd/push.go and cmd/pull.go use Client; see pkg/auth for
// the Get/HelperFunc library plugins use to reach this same store,
// importable from outside this module.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/alejandro-velasco/bomify/internal/layout"

	"oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// DefaultHost is the registry Login/Logout (and the `bomify
// login`/`bomify logout` commands built on them) target when none is
// given, matching `docker login`'s own default.
const DefaultHost = "docker.io"

// Store returns the credential store bomify reads and writes. Writes go
// to <dataDir>/conf/auth.json, a Docker-format config that delegates to
// the platform's native credential helper exactly as `docker login`'s
// does. Reads try it first, then Docker's own config, so an existing
// `docker login` still works; Logout never touches Docker's config.
// dataDir is $BOMIFY_DATA_DIR (which bomify sets for --data-dir) or
// ~/.bomify.
//
// Native helpers key secrets by host alone, so for a host logged into
// with both tools, they share one secret.
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
	primary, err := openAuthConfig(credentials.StoreOptions{
		DetectDefaultNativeStore: true,
	})
	if err != nil {
		return nil, err
	}
	docker, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return nil, err
	}
	return credentials.NewStoreWithFallbacks(primary, docker), nil
}

// newPlaintextStore is Login's fallback when no native credential helper
// is available: auth.json again, but willing to write a credential into
// it as plaintext rather than refusing. Factored out for the same
// test-isolation reason as newStore.
var newPlaintextStore = func() (*credentials.DynamicStore, error) {
	return openAuthConfig(credentials.StoreOptions{AllowPlaintextPut: true})
}

// openAuthConfig opens bomify's own auth.json (see Store) with opts.
func openAuthConfig(opts credentials.StoreOptions) (*credentials.DynamicStore, error) {
	dataDir, err := layout.DefaultDataDir()
	if err != nil {
		return nil, err
	}
	return credentials.NewStore(layout.AuthConfig(dataDir), opts)
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

// Client returns an oras-go auth.Client backed by the shared store, ready
// to attach to a remote.Repository or remote.Registry (see
// remote.Repository.Client).
func Client() (*orasauth.Client, error) {
	store, err := Store()
	if err != nil {
		return nil, err
	}

	httpClient := http.Client{
		Transport: transport,
	}
	client := orasauth.Client{
		Client:     &httpClient,
		Cache:      orasauth.NewCache(),
		Credential: credentials.Credential(store),
	}
	return &client, nil
}

// transport is the HTTP transport every Client shares, so each registry's
// connections are reused across repositories and layers. It's Go's
// default, but keeps as many idle connections per registry as overall:
// the default keeps 2, so with more layers transferring at once, every
// other one would open a new connection, and TLS handshake, of its own.
var transport = newTransport()

func newTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = transport.MaxIdleConns
	return transport
}

// LoginResult reports how Login stored a successfully verified
// credential.
type LoginResult struct {
	// PlaintextPath is set when no native credential helper was
	// available, so the credential was stored as plaintext in this config
	// file instead — the same fallback `docker login` makes when no
	// credsStore is configured.
	PlaintextPath string
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
		return LoginResult{PlaintextPath: plainStore.ConfigPath()}, nil
	}
	if err != nil {
		return LoginResult{}, fmt.Errorf("login to %s: %w", reg.Reference.Registry, err)
	}

	return LoginResult{}, nil
}

// Logout removes any credentials for host from bomify's own config (see
// Store).
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
