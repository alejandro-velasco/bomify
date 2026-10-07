package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"

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
	if result.PlaintextPath != "" {
		t.Errorf("PlaintextPath = %q, want empty (MemoryStore never rejects Put)", result.PlaintextPath)
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

// TestClientReusesConnections covers layers transferring at once: a
// second round of as many concurrent requests reuses the first round's
// connections, rather than all but 2 of them opening new ones.
func TestClientReusesConnections(t *testing.T) {
	useMemoryStore(t)
	const concurrent = 8

	var arrived sync.WaitGroup
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold every request until the whole round has arrived, so they
		// overlap and each needs a connection of its own.
		arrived.Done()
		arrived.Wait()
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)

	client, err := Client()
	if err != nil {
		t.Fatalf("Client() error = %v", err)
	}
	for range 2 {
		arrived.Add(concurrent)
		var done sync.WaitGroup
		for range concurrent {
			done.Go(func() {
				req, err := http.NewRequest(http.MethodGet, server.URL, nil)
				if err != nil {
					t.Errorf("new request: %v", err)
					return
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("GET: %v", err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			})
		}
		done.Wait()
	}

	if got := newConnections.Load(); got != concurrent {
		t.Errorf("opened %d connections over two rounds of %d requests, want %d", got, concurrent, concurrent)
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
	newPlaintextStore = func() (*credentials.DynamicStore, error) { return plaintextStore, nil }
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
	if result.PlaintextPath != configPath {
		t.Errorf("PlaintextPath = %q, want %q", result.PlaintextPath, configPath)
	}

	got, err := plaintextStore.Get(ctx, host)
	if err != nil {
		t.Fatalf("plaintextStore.Get: %v", err)
	}
	if got.Username != "alice" || got.Password != "s3cret" {
		t.Errorf("stored credential = %+v, want Username=alice Password=s3cret", got)
	}
}

// writePlaintextConfig writes a Docker-format config at path holding
// username/password for host in plaintext, so the real store reads it
// without touching any native credential helper.
func writePlaintextConfig(t *testing.T, path, host, username, password string) {
	t.Helper()

	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	content := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, encoded)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestStorePrefersAuthConfigAndFallsBackToDocker(t *testing.T) {
	dataDir, dockerDir := t.TempDir(), t.TempDir()
	t.Setenv(layout.DataDirEnv, dataDir)
	t.Setenv("DOCKER_CONFIG", dockerDir)

	ctx := context.Background()
	writePlaintextConfig(t, filepath.Join(dockerDir, "config.json"), "example.com", "docker-user", "docker-pass")

	cred, err := Lookup(ctx, "example.com")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if cred.Username != "docker-user" {
		t.Errorf("Lookup() with no auth.json = %+v, want docker's credential", cred)
	}

	writePlaintextConfig(t, layout.AuthConfig(dataDir), "example.com", "bomify-user", "bomify-pass")

	cred, err = Lookup(ctx, "example.com")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if cred.Username != "bomify-user" {
		t.Errorf("Lookup() = %+v, want auth.json's credential", cred)
	}

	if err := Logout(ctx, "example.com"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	cred, err = Lookup(ctx, "example.com")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if cred.Username != "docker-user" {
		t.Errorf("Lookup() after Logout = %+v, want docker's credential, left in place", cred)
	}
}

// TestSaveStoresWithoutVerifying covers a host that isn't a registry,
// which Login can't check: Save stores its credential as given, where
// Lookup finds it and Logout removes it.
func TestSaveStoresWithoutVerifying(t *testing.T) {
	useMemoryStore(t)
	ctx := context.Background()

	result, err := Save(ctx, "huggingface.co", "alice", "hf_token")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if result.PlaintextPath != "" {
		t.Errorf("PlaintextPath = %q, want none with a working store", result.PlaintextPath)
	}

	got, err := Lookup(ctx, "huggingface.co")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Username != "alice" || got.Password != "hf_token" {
		t.Errorf("Lookup = %+v, want alice/hf_token", got)
	}

	if err := Logout(ctx, "huggingface.co"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got, err := Lookup(ctx, "huggingface.co"); err != nil || got != orasauth.EmptyCredential {
		t.Errorf("Lookup after Logout = %+v, %v; want nothing", got, err)
	}
}

func TestSaveFallsBackToPlaintextWhenNoNativeHelperAvailable(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
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
	newPlaintextStore = func() (*credentials.DynamicStore, error) { return plaintextStore, nil }
	t.Cleanup(func() {
		newStore = originalStore
		newPlaintextStore = originalPlaintext
	})

	result, err := Save(context.Background(), "huggingface.co", "alice", "hf_token")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if result.PlaintextPath != configPath {
		t.Errorf("PlaintextPath = %q, want %q", result.PlaintextPath, configPath)
	}
	got, err := plaintextStore.Get(context.Background(), "huggingface.co")
	if err != nil || got.Password != "hf_token" {
		t.Errorf("stored credential = %+v, %v; want hf_token", got, err)
	}
}
