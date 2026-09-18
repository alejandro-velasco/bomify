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
	// Unprotected lists the SBOM content hashes of tagged builds whose
	// manifest exists but couldn't be parsed, so this Prune couldn't tell
	// which components to protect for them: unlike a simply-missing
	// manifest (nothing to protect either way), a tag still points at
	// this SBOM, so its components may have just been removed.
	Unprotected []string
}

// Prune removes every manifest and layer under baseDir that isn't
// reachable from a tag currently recorded in repositories.json.
//
// "Reachable" means: a tagged SBOM's own manifest file, plus the manifest
// and layer directory of every component that SBOM's actual content
// describes. Both kinds of manifest live in the same
// "manifests/<hash>.json" scheme with no distinguishing name, so rather
// than guess a file's kind from its content, Prune walks outward from
// repositories.json — the one place that actually says what's still in
// use — and removes everything in manifests/ and layers/ that walk never
// reached.
func Prune(baseDir string) (PruneResult, error) {
	kept, unprotected, err := reachableHashes(baseDir)
	if err != nil {
		return PruneResult{}, err
	}

	manifestsDir := filepath.Join(baseDir, "manifests")
	entries, err := os.ReadDir(manifestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return PruneResult{Unprotected: unprotected}, nil
		}
		return PruneResult{}, fmt.Errorf("read %s: %w", manifestsDir, err)
	}

	result := PruneResult{Unprotected: unprotected}
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
// the purl hash of every component that SBOM actually describes. It also
// returns the SBOM hash of every tagged build whose manifest exists but
// couldn't be parsed, so Prune can report that it wasn't able to protect
// that build's components — see PruneResult.Unprotected.
func reachableHashes(baseDir string) (kept map[string]bool, unprotected []string, err error) {
	repos, err := ReadRepositories(baseDir)
	if err != nil {
		return nil, nil, err
	}

	kept = map[string]bool{}
	for _, versions := range repos {
		for _, sbomHash := range versions {
			if kept[sbomHash] {
				continue
			}
			kept[sbomHash] = true
			if !markComponents(baseDir, sbomHash, kept) {
				unprotected = append(unprotected, sbomHash)
			}
		}
	}

	return kept, unprotected, nil
}

// markComponents parses the SBOM manifest for sbomHash and marks each
// component it describes as kept, reporting whether it was able to. A
// missing manifest is left alone and still reported as ok — whatever's
// kept from other tags still needs pruning correctly, and a manifest
// that isn't there has nothing to prune under it anyway — but a manifest
// that exists and fails to parse is reported as not ok: unlike "missing",
// this means there really are components here Prune can't identify, and
// so can't protect.
func markComponents(baseDir, sbomHash string, kept map[string]bool) (ok bool) {
	data, err := os.ReadFile(ManifestPath(baseDir, sbomHash))
	if err != nil {
		return true
	}

	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return false
	}
	if bom.Components == nil {
		return true
	}

	for _, component := range *bom.Components {
		kept[plugin.PurlHash(component)] = true
	}
	return true
}
