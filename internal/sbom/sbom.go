// Package sbom loads and inspects CycloneDX Software Bills of Materials.
package sbom

import (
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
