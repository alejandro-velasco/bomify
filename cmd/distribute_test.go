package cmd

import (
	"testing"

	"github.com/alejandro-velasco/bomify/internal/distribution"
)

func TestResolveRemotePrefersFlagOverRules(t *testing.T) {
	dataDir = t.TempDir()

	flags := map[string]string{"oci": "flag-registry"}
	rules := distribution.Config{
		{Type: "oci", Endpoint: "rule-registry"},
		{Type: "helm", Endpoint: "rule-charts"},
	}

	remote, err := resolveRemote("oci", "docker.io/myorg", flags, rules)
	if err != nil {
		t.Fatalf("resolveRemote: unexpected error: %v", err)
	}
	if remote != "flag-registry" {
		t.Errorf("resolveRemote: got %q, want %q", remote, "flag-registry")
	}
}

func TestResolveRemoteFallsBackToRules(t *testing.T) {
	dataDir = t.TempDir()

	flags := map[string]string{}
	rules := distribution.Config{{Type: "helm", Endpoint: "rule-charts"}}

	remote, err := resolveRemote("helm", "", flags, rules)
	if err != nil {
		t.Fatalf("resolveRemote: unexpected error: %v", err)
	}
	if remote != "rule-charts" {
		t.Errorf("resolveRemote: got %q, want %q", remote, "rule-charts")
	}
}

func TestResolveRemotePrefersMostSpecificRule(t *testing.T) {
	dataDir = t.TempDir()

	rules := distribution.Config{
		{Type: "oci", Endpoint: "generic-oci"},
		{Type: "oci", Match: "docker.io/myorg", Endpoint: "myorg-mirror"},
	}

	remote, err := resolveRemote("oci", "docker.io/myorg/myrepo", map[string]string{}, rules)
	if err != nil {
		t.Fatalf("resolveRemote: unexpected error: %v", err)
	}
	if remote != "myorg-mirror" {
		t.Errorf("resolveRemote: got %q, want %q", remote, "myorg-mirror")
	}
}

func TestResolveRemoteErrorsWhenNothingMatches(t *testing.T) {
	dataDir = t.TempDir()

	if _, err := resolveRemote("generic", "example.com", map[string]string{}, distribution.Config{}); err == nil {
		t.Fatal("resolveRemote: want error for an unconfigured kind, got nil")
	}
}
