package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

// PrunedItem describes one manifest or layer Prune removed.
type PrunedItem struct {
	// Kind is "manifest" or "layer".
	Kind string
	Path string
}

// PruneResult is the outcome of a Prune call.
type PruneResult struct {
	Removed []PrunedItem
	// Skipped lists manifest/layer paths Prune left alone because a pid
	// file suggested a pull might currently be in flight for them.
	Skipped []string
}

// Prune removes every manifest and layer under baseDir that isn't
// reachable from a tag currently recorded in repositories.json.
//
// "Reachable" means: a tagged SBOM's own manifest file, plus the
// manifest and layer directory of every component that SBOM's actual
// content describes. That last part matters — bomify has no way to tell
// an SBOM-level manifest file apart from a per-component one just from
// its name, since both live in the same "manifests/<hash>.json" scheme
// (keyed by the SBOM's own content hash and by each component's purl
// hash, respectively, which share no distinguishing prefix or directory).
// So rather than guess at a file's kind from its content, Prune walks
// outward from repositories.json — the one place that actually says
// what's still in use — marking everything it finds along the way, and
// removes everything else in manifests/ and layers/ that walk never
// reached.
func Prune(baseDir string) (PruneResult, error) {
	kept, err := reachableHashes(baseDir)
	if err != nil {
		return PruneResult{}, err
	}

	manifestsDir := filepath.Join(baseDir, "manifests")
	entries, err := os.ReadDir(manifestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return PruneResult{}, nil
		}
		return PruneResult{}, fmt.Errorf("read %s: %w", manifestsDir, err)
	}

	var result PruneResult
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		hash := strings.TrimSuffix(entry.Name(), ".json")
		if kept[hash] {
			continue
		}

		manifestPath := filepath.Join(manifestsDir, entry.Name())

		if _, err := os.Stat(filepath.Join(manifestsDir, hash+".pid")); err == nil {
			result.Skipped = append(result.Skipped, manifestPath)
			continue
		}

		if err := os.Remove(manifestPath); err != nil {
			return PruneResult{}, fmt.Errorf("remove %s: %w", manifestPath, err)
		}
		result.Removed = append(result.Removed, PrunedItem{Kind: "manifest", Path: manifestPath})

		layerDir := filepath.Join(baseDir, "layers", hash)
		if info, err := os.Stat(layerDir); err == nil && info.IsDir() {
			if err := os.RemoveAll(layerDir); err != nil {
				return PruneResult{}, fmt.Errorf("remove %s: %w", layerDir, err)
			}
			result.Removed = append(result.Removed, PrunedItem{Kind: "layer", Path: layerDir})
		}
	}

	return result, nil
}

// reachableHashes returns the set of manifest/layer hashes still
// reachable from repositories.json: every tagged SBOM's own hash, plus
// the purl hash of every component that SBOM actually describes.
func reachableHashes(baseDir string) (map[string]bool, error) {
	repos, err := ReadRepositories(baseDir)
	if err != nil {
		return nil, err
	}

	kept := map[string]bool{}
	for _, versions := range repos {
		for _, sbomHash := range versions {
			if kept[sbomHash] {
				continue
			}
			kept[sbomHash] = true
			markComponents(baseDir, sbomHash, kept)
		}
	}

	return kept, nil
}

// markComponents parses the SBOM manifest for sbomHash and marks each
// component it describes as kept. A missing or unparsable manifest is
// left alone rather than treated as an error: whatever's kept from other
// tags still needs pruning correctly, and a manifest that isn't there
// has nothing to prune under it anyway.
func markComponents(baseDir, sbomHash string, kept map[string]bool) {
	data, err := os.ReadFile(ManifestPath(baseDir, sbomHash))
	if err != nil {
		return
	}

	bom, err := sbom.LoadBytes(data)
	if err != nil || bom.Components == nil {
		return
	}

	for _, component := range *bom.Components {
		kept[plugin.PurlHash(component)] = true
	}
}
