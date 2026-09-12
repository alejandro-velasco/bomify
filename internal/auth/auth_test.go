package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	orasauth "oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
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

func TestGetReturnsEmptyWhenNothingStored(t *testing.T) {
	useMemoryStore(t)

	username, password, err := Get("example.com")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if username != "" || password != "" {
		t.Errorf("Get() = (%q, %q), want (\"\", \"\")", username, password)
	}
}

func TestLookupAndGetReturnStoredCredential(t *testing.T) {
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

	username, password, err := Get("example.com")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if username != want.Username || password != want.Password {
		t.Errorf("Get() = (%q, %q), want (%q, %q)", username, password, want.Username, want.Password)
	}
}

func TestGetFallsBackToRefreshToken(t *testing.T) {
	store := useMemoryStore(t)

	ctx := context.Background()
	if err := store.Put(ctx, "example.com", orasauth.Credential{RefreshToken: "a-refresh-token"}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	username, password, err := Get("example.com")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if username != "" || password != "a-refresh-token" {
		t.Errorf("Get() = (%q, %q), want (\"\", \"a-refresh-token\")", username, password)
	}
}

func TestHelperFuncAdaptsGet(t *testing.T) {
	store := useMemoryStore(t)

	ctx := context.Background()
	if err := store.Put(ctx, "example.com", orasauth.Credential{Username: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	var helper interface {
		Get(serverURL string) (string, string, error)
	} = HelperFunc(Get)

	username, password, err := helper.Get("example.com")
	if err != nil {
		t.Fatalf("helper.Get() error = %v", err)
	}
	if username != "alice" || password != "s3cret" {
		t.Errorf("helper.Get() = (%q, %q), want (\"alice\", \"s3cret\")", username, password)
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
	if err := loginToRegistry(ctx, plainHTTPRegistry(host), "alice", "s3cret"); err != nil {
		t.Fatalf("loginToRegistry() error = %v", err)
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
	err := loginToRegistry(ctx, plainHTTPRegistry(host), "alice", "wrong-password")
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
