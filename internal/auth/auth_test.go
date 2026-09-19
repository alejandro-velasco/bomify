package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// useMemoryStore swaps newStore for the duration of the test to an
// in-memory credentials.Store, so tests never touch this machine's real
// Docker config file or native credential helper (which Store's real
// implementation would otherwise auto-detect and write real, shared,
// system-wide state into).
func useMemoryStore(t *testing.T) credentials.Store {
	t.Helper()

	store := credentials.NewMemoryStore()
	original := newStore
	newStore = func() (credentials.Store, error) { return store, nil }
	t.Cleanup(func() { newStore = original })

	return store
}

func TestLookupReturnsEmptyWhenNothingStored(t *testing.T) {
	useMemoryStore(t)

	cred, err := Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if cred != orasauth.EmptyCredential {
		t.Errorf("Lookup() = %+v, want EmptyCredential", cred)
	}
}

func TestLookupReturnsStoredCredential(t *testing.T) {
	store := useMemoryStore(t)

	ctx := context.Background()
	want := orasauth.Credential{Username: "alice", Password: "s3cret"}
	if err := store.Put(ctx, "example.com", want); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	cred, err := Lookup(ctx, "example.com")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if cred != want {
		t.Errorf("Lookup() = %+v, want %+v", cred, want)
	}
}

// fakeRegistry is a minimal OCI distribution-spec server for exercising a
// real login attempt end to end: it answers the base API check
// (GET /v2/) exactly as a real registry would when challenging and then
// accepting Basic auth, without implementing anything else a registry
// does.
func fakeRegistry(t *testing.T, wantUsername, wantPassword string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || username != wantUsername || password != wantPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="fake registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
}

func plainHTTPRegistry(host string) *remote.Registry {
	reg := &remote.Registry{}
	reg.Reference = registry.Reference{Registry: host}
	reg.PlainHTTP = true
	return reg
}

func TestLoginVerifiesThenStoresCredential(t *testing.T) {
	store := useMemoryStore(t)

	srv := fakeRegistry(t, "alice", "s3cret")
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	ctx := context.Background()
	result, err := loginToRegistry(ctx, plainHTTPRegistry(host), "alice", "s3cret")
	if err != nil {
		t.Fatalf("loginToRegistry() error = %v", err)
	}
	if result.PlaintextFallback {
		t.Error("PlaintextFallback = true, want false (MemoryStore never rejects Put)")
	}

	got, err := store.Get(ctx, host)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.Username != "alice" || got.Password != "s3cret" {
		t.Errorf("stored credential = %+v, want Username=alice Password=s3cret", got)
	}
}

func TestLoginRejectsWrongCredentialWithoutStoring(t *testing.T) {
	store := useMemoryStore(t)

	srv := fakeRegistry(t, "alice", "s3cret")
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	ctx := context.Background()
	_, err := loginToRegistry(ctx, plainHTTPRegistry(host), "alice", "wrong-password")
	if err == nil {
		t.Fatal("loginToRegistry() error = nil, want error for wrong password")
	}

	got, getErr := store.Get(ctx, host)
	if getErr != nil {
		t.Fatalf("store.Get: %v", getErr)
	}
	if got != orasauth.EmptyCredential {
		t.Errorf("credential stored despite failed login: %+v", got)
	}
}

func TestLogoutRemovesStoredCredential(t *testing.T) {
	store := useMemoryStore(t)

	ctx := context.Background()
	if err := store.Put(ctx, "example.com", orasauth.Credential{Username: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	if err := Logout(ctx, "example.com"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	got, err := store.Get(ctx, "example.com")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got != orasauth.EmptyCredential {
		t.Errorf("credential still present after Logout: %+v", got)
	}
}

func TestClientUsesSharedStore(t *testing.T) {
	store := useMemoryStore(t)

	ctx := context.Background()
	if err := store.Put(ctx, "example.com", orasauth.Credential{Username: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	client, err := Client()
	if err != nil {
		t.Fatalf("Client() error = %v", err)
	}

	cred, err := client.Credential(ctx, "example.com")
	if err != nil {
		t.Fatalf("client.Credential() error = %v", err)
	}
	if cred.Username != "alice" || cred.Password != "s3cret" {
		t.Errorf("client.Credential() = %+v, want Username=alice Password=s3cret", cred)
	}
}

// TestLoginFallsBackToPlaintextWhenNoNativeHelperAvailable reproduces the
// real bug this test guards against: on a machine with no native
// credential helper configured, credentials.Login's store step used to
// fail outright with ErrPlaintextPutDisabled, blocking `bomify login`
// entirely even though the credentials were verified as correct. Login
// should instead fall back to storing them as plaintext, the same
// fallback `docker login` itself takes.
func TestLoginFallsBackToPlaintextWhenNoNativeHelperAvailable(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")

	// A real DynamicStore over a fresh config file with no credsStore
	// configured and no auto-detection — deterministically reproducing
	// "no native helper available" regardless of what's actually on the
	// machine running this test.
	blockingStore, err := credentials.NewStore(configPath, credentials.StoreOptions{})
	if err != nil {
		t.Fatalf("NewStore (blocking): %v", err)
	}
	plaintextStore, err := credentials.NewStore(configPath, credentials.StoreOptions{AllowPlaintextPut: true})
	if err != nil {
		t.Fatalf("NewStore (plaintext): %v", err)
	}

	originalStore, originalPlaintext := newStore, newPlaintextStore
	newStore = func() (credentials.Store, error) { return blockingStore, nil }
	newPlaintextStore = func() (credentials.Store, error) { return plaintextStore, nil }
	t.Cleanup(func() {
		newStore = originalStore
		newPlaintextStore = originalPlaintext
	})

	srv := fakeRegistry(t, "alice", "s3cret")
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	ctx := context.Background()

	// Sanity check: without the fallback, this really does fail exactly
	// as the user reported.
	if err := blockingStore.Put(ctx, host, orasauth.Credential{Username: "x", Password: "y"}); err == nil {
		t.Fatal("blockingStore.Put() error = nil, want ErrPlaintextPutDisabled (test setup is wrong)")
	} else if err := blockingStore.Delete(ctx, host); err != nil {
		t.Fatalf("clean up sanity-check credential: %v", err)
	}

	result, err := loginToRegistry(ctx, plainHTTPRegistry(host), "alice", "s3cret")
	if err != nil {
		t.Fatalf("loginToRegistry() error = %v", err)
	}
	if !result.PlaintextFallback {
		t.Error("PlaintextFallback = false, want true")
	}

	got, err := plaintextStore.Get(ctx, host)
	if err != nil {
		t.Fatalf("plaintextStore.Get: %v", err)
	}
	if got.Username != "alice" || got.Password != "s3cret" {
		t.Errorf("stored credential = %+v, want Username=alice Password=s3cret", got)
	}
}
