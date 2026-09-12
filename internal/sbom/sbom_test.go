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

func TestLoadBytesDetectsJSON(t *testing.T) {
	data := []byte(`  {"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"component":{"type":"application","name":"example-app"}}}`)

	bom, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if got, want := bom.Metadata.Component.Name, "example-app"; got != want {
		t.Errorf("root component name = %q, want %q", got, want)
	}
}

func TestLoadBytesDetectsXML(t *testing.T) {
	data := []byte(`
<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata>
    <component type="application">
      <name>example-app</name>
    </component>
  </metadata>
</bom>`)

	bom, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if got, want := bom.Metadata.Component.Name, "example-app"; got != want {
		t.Errorf("root component name = %q, want %q", got, want)
	}
}

func TestLoadBytesRejectsUnrecognized(t *testing.T) {
	if _, err := LoadBytes([]byte("not an sbom")); err == nil {
		t.Fatal("LoadBytes() with unrecognized content: expected error, got nil")
	}
}

func TestLoadBytesRejectsEmpty(t *testing.T) {
	if _, err := LoadBytes([]byte("   ")); err == nil {
		t.Fatal("LoadBytes() with empty content: expected error, got nil")
	}
}
