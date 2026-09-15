package sbom

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestLoadJSON(t *testing.T) {
	bom, err := Load("../../testdata/example.cdx.json")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got, want := bom.Metadata.Component.Name, "example-app"; got != want {
		t.Errorf("root component name = %q, want %q", got, want)
	}
}

func TestLoadXML(t *testing.T) {
	bom, err := Load("../../testdata/example.cdx.xml")
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

// utf8BOMBytes is the raw UTF-8 byte-order-mark some tools prepend to
// "UTF-8" files — real-world input LoadBytes/DetectFormat must tolerate,
// since it isn't Unicode whitespace and so survives a naive
// bytes.TrimSpace untouched.
var utf8BOMBytes = []byte{0xEF, 0xBB, 0xBF}

func TestLoadBytesStripsLeadingBOMFromXML(t *testing.T) {
	data := append(append([]byte{}, utf8BOMBytes...), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata>
    <component type="application">
      <name>example-app</name>
    </component>
  </metadata>
</bom>`)...)

	bom, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if got, want := bom.Metadata.Component.Name, "example-app"; got != want {
		t.Errorf("root component name = %q, want %q", got, want)
	}
}

func TestLoadBytesStripsLeadingBOMFromJSON(t *testing.T) {
	data := append(append([]byte{}, utf8BOMBytes...),
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"component":{"type":"application","name":"example-app"}}}`)...)

	bom, err := LoadBytes(data)
	if err != nil {
		t.Fatalf("LoadBytes returned error: %v", err)
	}
	if got, want := bom.Metadata.Component.Name, "example-app"; got != want {
		t.Errorf("root component name = %q, want %q", got, want)
	}
}

func TestDetectFormatStripsLeadingBOM(t *testing.T) {
	data := append(append([]byte{}, utf8BOMBytes...), []byte(`<bom/>`)...)

	format, err := DetectFormat(data)
	if err != nil {
		t.Fatalf("DetectFormat returned error: %v", err)
	}
	if format != cdx.BOMFileFormatXML {
		t.Errorf("DetectFormat() = %v, want BOMFileFormatXML", format)
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
