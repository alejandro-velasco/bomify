package build

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

// PackageSize returns the total on-disk size, in bytes, of every
// component the SBOM for sbomHash describes — the sum of each distinct
// purl's layer directory under "<baseDir>/layers", mirroring the same
// walk Prune uses to find a tag's reachable components (see
// reachableHashes/markComponents). A component named more than once by
// the same SBOM is only counted once, since duplicate purls share the
// same layer directory. A component that hasn't been pulled yet (no
// layer directory) contributes 0, rather than erroring — matching
// PackageSize to whatever's actually on disk right now.
func PackageSize(baseDir, sbomHash string) (int64, error) {
	data, err := os.ReadFile(ManifestPath(baseDir, sbomHash))
	if err != nil {
		return 0, fmt.Errorf("read manifest %s: %w", sbomHash, err)
	}

	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return 0, fmt.Errorf("parse manifest %s: %w", sbomHash, err)
	}
	if bom.Components == nil {
		return 0, nil
	}

	seen := map[string]bool{}
	var total int64
	for _, component := range *bom.Components {
		hash := plugin.PurlHash(component)
		if seen[hash] {
			continue
		}
		seen[hash] = true

		size, err := dirSize(filepath.Join(baseDir, "layers", hash))
		if err != nil {
			return 0, err
		}
		total += size
	}

	return total, nil
}

// dirSize returns the total size, in bytes, of every regular file under
// dir, walked recursively — 0 if dir doesn't exist yet.
func dirSize(dir string) (int64, error) {
	var total int64

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("walk %s: %w", dir, err)
	}

	return total, nil
}
