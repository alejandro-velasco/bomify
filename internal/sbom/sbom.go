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

	format := cdx.BOMFileFormatJSON
	if strings.EqualFold(strings.TrimPrefix(fileExt(path), "."), "xml") {
		format = cdx.BOMFileFormatXML
	}

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(f, format)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decode sbom: %w", err)
	}

	return bom, nil
}

// ComponentCount returns the number of components declared in the BOM.
func ComponentCount(bom *cdx.BOM) int {
	if bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}

func fileExt(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx == -1 {
		return ""
	}
	return path[idx:]
}
