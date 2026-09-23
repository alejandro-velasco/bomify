package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

func TestPackagesListsSize(t *testing.T) {
	origDataDir := dataDir
	defer func() { dataDir = origDataDir }()
	dataDir = t.TempDir()

	component := cdx.Component{Name: "nginx", Version: "1.27", PackageURL: "pkg:oci/nginx@1.27"}

	// A pulled layer of a known size (10 bytes), so PackageSize's sum is
	// predictable.
	layerDir := filepath.Join(dataDir, "layers", plugin.PurlHash(component))
	if err := os.MkdirAll(layerDir, 0o755); err != nil {
		t.Fatalf("mkdir layer dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "artifact"), []byte("0123456789"), 0o644); err != nil {
		t.Fatalf("write layer file: %v", err)
	}

	sbom := struct {
		BOMFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		Version     int             `json:"version"`
		Components  []cdx.Component `json:"components"`
	}{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Components:  []cdx.Component{component},
	}
	sbomData, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("marshal sbom: %v", err)
	}
	sbomPath := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomData, 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	sbomHash, _, err := build.RecordManifest(dataDir, sbomPath)
	if err != nil {
		t.Fatalf("RecordManifest: %v", err)
	}
	if err := build.UpdateRepositories(dataDir, []string{"myapp:latest"}, sbomHash); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	if err := runPackages(cmd, &packagesOptions{}); err != nil {
		t.Fatalf("runPackages() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "SIZE") {
		t.Errorf("output missing SIZE header:\n%s", out)
	}
	if !strings.Contains(out, "10.0b") {
		t.Errorf("output missing expected 10.0b size for the 10-byte layer:\n%s", out)
	}
}

func TestPackagesEmptyRepositoriesListsHeaderOnly(t *testing.T) {
	origDataDir := dataDir
	defer func() { dataDir = origDataDir }()
	dataDir = t.TempDir()

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	if err := runPackages(cmd, &packagesOptions{}); err != nil {
		t.Fatalf("runPackages() error = %v", err)
	}

	out := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(out, "REPOSITORY") {
		t.Errorf("output = %q, want just the header row", out)
	}
	if strings.Count(out, "\n") != 0 {
		t.Errorf("output = %q, want a single header line with no data rows", out)
	}
}
