package distribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReadMissingFile(t *testing.T) {
	config, err := Read(t.TempDir())
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}
	if len(config) != 0 {
		t.Fatalf("Read: want empty config, got %v", config)
	}
}

func TestReadParsesEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(ConfigPath(dir)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	const raw = `{
		"oci": {"endpoint": "local-registry/foo"},
		"helm": {"endpoint": "local-registry/helm"}
	}`
	if err := os.WriteFile(ConfigPath(dir), []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}

	want := map[string]string{"oci": "local-registry/foo", "helm": "local-registry/helm"}
	if len(config) != len(want) {
		t.Fatalf("Read: got %v, want %v", config, want)
	}
	for kind, endpoint := range want {
		if config[kind].Endpoint != endpoint {
			t.Errorf("config[%q].Endpoint = %q, want %q", kind, config[kind].Endpoint, endpoint)
		}
	}
}

func TestReadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(ConfigPath(dir)), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ConfigPath(dir), []byte("not json"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Read(dir); err == nil {
		t.Fatal("Read: want error for invalid JSON, got nil")
	}
}

func TestRemotesFlattensConfig(t *testing.T) {
	dir := t.TempDir()

	if err := SetEndpoint(dir, "oci", "local-registry/foo"); err != nil {
		t.Fatalf("SetEndpoint: unexpected error: %v", err)
	}

	remotes, err := Remotes(dir)
	if err != nil {
		t.Fatalf("Remotes: unexpected error: %v", err)
	}
	if remotes["oci"] != "local-registry/foo" {
		t.Errorf("Remotes()[oci] = %q, want %q", remotes["oci"], "local-registry/foo")
	}
}

func TestSetEndpointWritesNewEntry(t *testing.T) {
	dir := t.TempDir()

	if err := SetEndpoint(dir, "oci", "local-registry/foo"); err != nil {
		t.Fatalf("SetEndpoint: unexpected error: %v", err)
	}

	data, err := os.ReadFile(ConfigPath(dir))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if got := config["oci"].Endpoint; got != "local-registry/foo" {
		t.Errorf("config[oci].Endpoint = %q, want %q", got, "local-registry/foo")
	}
}

func TestSetEndpointMergesWithExisting(t *testing.T) {
	dir := t.TempDir()

	if err := SetEndpoint(dir, "oci", "local-registry/foo"); err != nil {
		t.Fatalf("SetEndpoint(oci): unexpected error: %v", err)
	}
	if err := SetEndpoint(dir, "helm", "local-registry/helm"); err != nil {
		t.Fatalf("SetEndpoint(helm): unexpected error: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}

	want := map[string]string{"oci": "local-registry/foo", "helm": "local-registry/helm"}
	if len(config) != len(want) {
		t.Fatalf("Read: got %v, want %v", config, want)
	}
	for kind, endpoint := range want {
		if config[kind].Endpoint != endpoint {
			t.Errorf("config[%q].Endpoint = %q, want %q", kind, config[kind].Endpoint, endpoint)
		}
	}
}

func TestSetEndpointOverwritesExistingKind(t *testing.T) {
	dir := t.TempDir()

	if err := SetEndpoint(dir, "oci", "old-endpoint"); err != nil {
		t.Fatalf("SetEndpoint: unexpected error: %v", err)
	}
	if err := SetEndpoint(dir, "oci", "new-endpoint"); err != nil {
		t.Fatalf("SetEndpoint: unexpected error: %v", err)
	}

	config, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: unexpected error: %v", err)
	}

	if got := config["oci"].Endpoint; got != "new-endpoint" {
		t.Errorf("config[oci].Endpoint = %q, want %q", got, "new-endpoint")
	}
}
