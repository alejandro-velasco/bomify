// Package sbom loads and inspects CycloneDX Software Bills of Materials.
package sbom

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Load reads a CycloneDX SBOM from path, auto-detecting JSON or XML encoding
// from the file extension.
func Load(path string) (*cdx.BOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sbom: %w", err)
	}
	defer f.Close()

	format, err := fileFormat(path)
	if err != nil {
		return nil, fmt.Errorf("detect sbom format: %w", err)
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(f, format)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decode sbom: %w", err)
	}

	return bom, nil
}

// LoadBytes parses a CycloneDX SBOM from data, detecting JSON vs XML from
// its content (its first non-whitespace byte) rather than a file
// extension. Use this for an SBOM that isn't sitting behind a
// trustworthy .json/.xml path — e.g. internal/build's recorded manifests,
// which are always named "<hash>.json" regardless of the original SBOM's
// real format, since RecordManifest copies it verbatim.
//
// A leading UTF-8 byte-order-mark, if present, is stripped before
// detection and decoding — see utf8BOM. This strip is done here, up
// front, rather than left to DetectFormat's own (also necessary — see
// its doc comment) one: DetectFormat only returns a format, not cleaned
// bytes, and the decoder below needs BOM-free input to work at all
// (confirmed experimentally: Go's JSON decoder, unlike its XML one,
// rejects a raw BOM even once the format is already known).
func LoadBytes(data []byte) (*cdx.BOM, error) {
	data = bytes.TrimPrefix(data, utf8BOM)

	format, err := DetectFormat(data)
	if err != nil {
		return nil, fmt.Errorf("detect sbom format: %w", err)
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(data), format)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decode sbom: %w", err)
	}

	return bom, nil
}

// utf8BOM is the UTF-8 byte-order-mark some tools — XML writers
// especially, and text editors on Windows — prepend to files they save
// as "UTF-8". It's invisible in most editors and, since it isn't
// Unicode whitespace, survives bytes.TrimSpace untouched: left alone, it
// makes DetectFormat see neither '{' nor '<' and misreport the SBOM as
// unrecognized, and makes Go's JSON decoder (though not, as it happens,
// its XML one) fail outright even once the format is known. LoadBytes
// and DetectFormat both strip it before doing anything else.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// DetectFormat detects data's CycloneDX BOMFileFormat from its first
// non-whitespace byte, after stripping a leading UTF-8 byte-order-mark if
// present (see utf8BOM): '{' for JSON, '<' for XML. Exported so callers
// that need to know the format for a reason other than parsing it (e.g.
// internal/oci/push choosing a media type for the raw bytes it's about to
// push) don't have to re-implement the same sniffing LoadBytes does.
func DetectFormat(data []byte) (cdx.BOMFileFormat, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
	if len(trimmed) == 0 {
		return 0, fmt.Errorf("empty sbom")
	}

	switch trimmed[0] {
	case '{':
		return cdx.BOMFileFormatJSON, nil
	case '<':
		return cdx.BOMFileFormatXML, nil
	default:
		return 0, fmt.Errorf("unrecognized sbom content (starts with %q)", trimmed[0])
	}
}

// fileFormat returns the CycloneDX BOMFileFormat corresponding to the file extension of path.
func fileFormat(path string) (cdx.BOMFileFormat, error) {
	idx := strings.LastIndex(path, ".")
	if idx == -1 {
		return 0, fmt.Errorf("cannot determine file format from path %q", path)
	}
	fileExt := strings.TrimPrefix(path[idx:], ".")

	switch strings.ToLower(fileExt) {
	case "xml":
		return cdx.BOMFileFormatXML, nil
	case "json":
		return cdx.BOMFileFormatJSON, nil
	default:
		return 0, fmt.Errorf("unsupported file format %q", fileExt)
	}
}
