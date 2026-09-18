// Package auth is the Go library a bomify plugin uses to reach bomify's
// shared registry credential store: Get returns whatever credentials are
// stored for a server, and HelperFunc adapts it to the single-method
// credential-helper interface several third-party SDKs
// (docker-credential-helpers, go-containerregistry) expect. The store
// itself — reading Docker's config.json plus the native OS credential
// helper — lives in internal/auth; unlike that package, this one is
// importable from any Go module, so a third-party plugin can depend on
// it directly.
package auth

import (
	"context"
	"errors"

	orasauth "oras.land/oras-go/v2/registry/remote/auth"

	internalauth "github.com/alejandro-velasco/bomify/internal/auth"
)

// Get returns just the username and secret stored for serverURL, or two
// empty strings if none are stored. Its signature deliberately matches
// the "Get(serverURL string) (string, string, error)" shape several
// third-party credential-helper interfaces use, so plugins can hand it
// straight to whatever SDK they call (see HelperFunc).
func Get(serverURL string) (string, string, error) {
	cred, err := internalauth.Lookup(context.Background(), serverURL)
	if err != nil {
		return "", "", err
	}

	username, password := credentialToUserPass(cred)
	return username, password, nil
}

// credentialToUserPass extracts a (username, password) pair from cred,
// falling back to a registry's refresh or access token — still a real
// secret worth handing over — when cred has no username, and to two
// empty strings when cred is empty.
func credentialToUserPass(cred orasauth.Credential) (string, string) {
	if cred.Username != "" {
		return cred.Username, cred.Password
	}

	switch {
	case cred.RefreshToken != "":
		return "", cred.RefreshToken
	case cred.AccessToken != "":
		return "", cred.AccessToken
	default:
		return "", ""
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
