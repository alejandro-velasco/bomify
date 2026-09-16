package cmd

import "testing"

func TestResolveRemotePrefersFlagOverFallback(t *testing.T) {
	dataDir = t.TempDir()

	flags := map[string]string{"oci": "flag-registry"}
	fallback := map[string]string{"oci": "fallback-registry", "helm": "fallback-charts"}

	remote, err := resolveRemote("oci", flags, fallback)
	if err != nil {
		t.Fatalf("resolveRemote: unexpected error: %v", err)
	}
	if remote != "flag-registry" {
		t.Errorf("resolveRemote: got %q, want %q", remote, "flag-registry")
	}
}

func TestResolveRemoteFallsBackToConfig(t *testing.T) {
	dataDir = t.TempDir()

	flags := map[string]string{}
	fallback := map[string]string{"helm": "fallback-charts"}

	remote, err := resolveRemote("helm", flags, fallback)
	if err != nil {
		t.Fatalf("resolveRemote: unexpected error: %v", err)
	}
	if remote != "fallback-charts" {
		t.Errorf("resolveRemote: got %q, want %q", remote, "fallback-charts")
	}
}

func TestResolveRemoteErrorsWhenKindMissing(t *testing.T) {
	dataDir = t.TempDir()

	if _, err := resolveRemote("generic", map[string]string{}, map[string]string{}); err == nil {
		t.Fatal("resolveRemote: want error for unconfigured kind, got nil")
	}
}
