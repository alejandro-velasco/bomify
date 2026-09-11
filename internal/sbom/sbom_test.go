package sbom

import "testing"

func TestLoadJSON(t *testing.T) {
	bom, err := Load("../../testdata/example.cdx.json")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got, want := bom.Metadata.Component.Name, "example-app"; got != want {
		t.Errorf("root component name = %q, want %q", got, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("../../testdata/does-not-exist.cdx.json"); err == nil {
		t.Fatal("Load() with missing file: expected error, got nil")
	}
}
