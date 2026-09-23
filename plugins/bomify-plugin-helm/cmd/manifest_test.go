package cmd

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
)

func TestLoadManifestMissingDefaultIsNotAnError(t *testing.T) {
	m, err := loadManifest(filepath.Join(t.TempDir(), "does-not-exist.yaml"), false)
	if err != nil {
		t.Fatalf("loadManifest() error = %v, want nil for a missing default manifest", err)
	}
	if m.Chart != "" || m.Repo != "" || m.Version != "" || len(m.Values) != 0 ||
		m.Namespace != "" || m.ReleaseName != "" || m.KubeVersion != "" || m.Output != "" {
		t.Errorf("loadManifest() = %+v, want the zero manifest", m)
	}
}

func TestLoadManifestMissingExplicitIsAnError(t *testing.T) {
	if _, err := loadManifest(filepath.Join(t.TempDir(), "does-not-exist.yaml"), true); err == nil {
		t.Fatal("loadManifest() error = nil, want an error for an explicitly-named missing manifest")
	}
}

func TestLoadManifestParsesEveryField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	writeFile(t, path, `
chart: postgresql
repo: oci://registry-1.docker.io/bitnamicharts
version: 18.11.6
values:
  - values.yaml
  - values-prod.yaml
namespace: prod
release-name: myrelease
kube-version: 1.31.0
output: postgresql.cdx.json
`)

	m, err := loadManifest(path, true)
	if err != nil {
		t.Fatalf("loadManifest() error = %v", err)
	}

	want := manifest{
		Chart:       "postgresql",
		Repo:        "oci://registry-1.docker.io/bitnamicharts",
		Version:     "18.11.6",
		Values:      []string{"values.yaml", "values-prod.yaml"},
		Namespace:   "prod",
		ReleaseName: "myrelease",
		KubeVersion: "1.31.0",
		Output:      "postgresql.cdx.json",
	}
	if m.Chart != want.Chart || m.Repo != want.Repo || m.Version != want.Version ||
		m.Namespace != want.Namespace || m.ReleaseName != want.ReleaseName ||
		m.KubeVersion != want.KubeVersion || m.Output != want.Output ||
		len(m.Values) != len(want.Values) || m.Values[0] != want.Values[0] || m.Values[1] != want.Values[1] {
		t.Errorf("loadManifest() = %+v, want %+v", m, want)
	}
}

func TestLoadManifestParsesExtraComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	writeFile(t, path, `
chart: postgresql
repo: oci://registry-1.docker.io/bitnamicharts
extraComponents:
  - type: library
    name: some-lib
    version: "1.0"
    purl: "pkg:generic/some-lib@1.0"
`)

	m, err := loadManifest(path, true)
	if err != nil {
		t.Fatalf("loadManifest() error = %v", err)
	}

	if len(m.ExtraComponents) != 1 {
		t.Fatalf("ExtraComponents = %+v, want 1 entry", m.ExtraComponents)
	}
	got := m.ExtraComponents[0]
	if got.Type != cdx.ComponentTypeLibrary || got.Name != "some-lib" || got.Version != "1.0" || got.PackageURL != "pkg:generic/some-lib@1.0" {
		t.Errorf("ExtraComponents[0] = %+v, want type=library name=some-lib version=1.0 purl=pkg:generic/some-lib@1.0", got)
	}
}

func TestAppendExtraComponents(t *testing.T) {
	existing := []cdx.Component{{Name: "chart-component"}}
	extra := []cdx.Component{{Name: "custom-one"}, {Name: "custom-two"}}

	got := appendExtraComponents(existing, extra)

	want := []string{"chart-component", "custom-one", "custom-two"}
	if len(got) != len(want) {
		t.Fatalf("appendExtraComponents() = %+v, want %d entries", got, len(want))
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("appendExtraComponents()[%d].Name = %q, want %q", i, got[i].Name, name)
		}
	}
}

func TestAppendExtraComponentsEmpty(t *testing.T) {
	existing := []cdx.Component{{Name: "chart-component"}}

	got := appendExtraComponents(existing, nil)

	if len(got) != 1 || got[0].Name != "chart-component" {
		t.Errorf("appendExtraComponents() with no extra = %+v, want unchanged", got)
	}
}

func TestLoadManifestMalformedYAMLErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	writeFile(t, path, "chart: [this is not a string\n")

	if _, err := loadManifest(path, true); err == nil {
		t.Fatal("loadManifest() error = nil, want an error for malformed YAML")
	}
}

// stringFlagCmd builds a minimal *cobra.Command with a single string
// flag registered under name, defaulting to flagDefault — just enough
// for resolveString/resolveValues to inspect via cmd.Flags().Changed.
func stringFlagCmd(t *testing.T, name, flagDefault string, changedTo string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String(name, flagDefault, "")
	if changedTo != "" {
		if err := cmd.Flags().Set(name, changedTo); err != nil {
			t.Fatalf("set flag %s: %v", name, err)
		}
	}
	return cmd
}

func TestResolveStringFlagChangedWins(t *testing.T) {
	cmd := stringFlagCmd(t, "chart", "", "from-flag")
	if got := resolveString(cmd, "chart", "from-flag", "from-manifest"); got != "from-flag" {
		t.Errorf("resolveString() = %q, want %q", got, "from-flag")
	}
}

func TestResolveStringFallsBackToManifest(t *testing.T) {
	cmd := stringFlagCmd(t, "chart", "", "")
	if got := resolveString(cmd, "chart", "", "from-manifest"); got != "from-manifest" {
		t.Errorf("resolveString() = %q, want %q", got, "from-manifest")
	}
}

func TestResolveStringFallsBackToFlagDefaultWhenManifestEmpty(t *testing.T) {
	// Simulates --namespace's own non-empty default ("default"): unset by
	// the user and absent from the manifest, so the flag's own default
	// must win rather than an empty manifest value clobbering it.
	cmd := stringFlagCmd(t, "namespace", "default", "")
	if got := resolveString(cmd, "namespace", "default", ""); got != "default" {
		t.Errorf("resolveString() = %q, want %q", got, "default")
	}
}

func TestResolveValuesFlagChangedWins(t *testing.T) {
	cmd := stringFlagCmd(t, "values", "", "ignored")
	// "values" is a repeatable flag in the real command; Changed is all
	// resolveValues actually inspects, so a single-string flag stand-in
	// is enough to drive it.
	got := resolveValues(cmd, []string{"a.yaml"}, []string{"b.yaml"})
	if len(got) != 1 || got[0] != "a.yaml" {
		t.Errorf("resolveValues() = %v, want [a.yaml]", got)
	}
}

func TestResolveValuesFallsBackToManifest(t *testing.T) {
	cmd := stringFlagCmd(t, "values", "", "")
	got := resolveValues(cmd, nil, []string{"b.yaml"})
	if len(got) != 1 || got[0] != "b.yaml" {
		t.Errorf("resolveValues() = %v, want [b.yaml]", got)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
