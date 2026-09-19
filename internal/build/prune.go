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
	// Skipped lists the hashes of components Prune left alone because a
	// pid file names a still-live process — a pull genuinely in flight
	// for them (see plugin.PIDFileLive). A pid file left behind by a
	// pull that crashed without cleaning up does not count: Prune
	// reclaims that component instead of skipping it.
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
// "Reachable" means: a tagged SBOM's own manifest, plus the manifest and
// layer directory of every component that SBOM describes. Both kinds of
// manifest share the same "manifests/<hash>.json" naming with no way to
// tell them apart by content alone, so Prune walks outward from
// repositories.json instead of guessing — the one place that says what's
// still in use.
//
// Candidates are gathered from both manifests/ and layers/, not just
// manifests/: `bomify build` writes a manifest for every component, but
// `bomify pull` writes only the SBOM-level manifest — a pulled
// component's layer directory has no manifest of its own. Relying on
// manifests/ alone would leave such a directory permanently
// undiscovered, however unreachable it becomes.
func Prune(baseDir string) (PruneResult, error) {
	kept, unprotected, err := reachableHashes(baseDir)
	if err != nil {
		return PruneResult{}, err
	}

	manifestsDir := filepath.Join(baseDir, "manifests")
	layersDir := filepath.Join(baseDir, "layers")

	hashes, err := candidateHashes(manifestsDir, layersDir)
	if err != nil {
		return PruneResult{}, err
	}

	result := PruneResult{Unprotected: unprotected}
	for _, hash := range hashes {
		if kept[hash] {
			continue
		}

		if plugin.PIDFileLive(filepath.Join(manifestsDir, hash+".pid")) {
			result.Skipped = append(result.Skipped, hash)
			continue
		}
		// A stale pid file (its process crashed without cleaning up)
		// doesn't block reclaiming this component; remove it too, so a
		// future Prune doesn't need to re-derive that it's stale.
		os.Remove(filepath.Join(manifestsDir, hash+".pid"))

		manifestPath := filepath.Join(manifestsDir, hash+".json")
		if _, err := os.Stat(manifestPath); err == nil {
			if err := os.Remove(manifestPath); err != nil {
				return PruneResult{}, fmt.Errorf("remove %s: %w", manifestPath, err)
			}
			result.Removed = append(result.Removed, PrunedItem{Kind: "manifest", Path: manifestPath})
		}

		layerDir := filepath.Join(layersDir, hash)
		if info, err := os.Stat(layerDir); err == nil && info.IsDir() {
			if err := os.RemoveAll(layerDir); err != nil {
				return PruneResult{}, fmt.Errorf("remove %s: %w", layerDir, err)
			}
			result.Removed = append(result.Removed, PrunedItem{Kind: "layer", Path: layerDir})
		}
	}

	return result, nil
}

// candidateHashes returns every hash with either a manifest file under
// manifestsDir or a layer directory under layersDir (or both) — i.e.
// every hash Prune might need to reclaim. A missing directory
// contributes no candidates rather than erroring, since a fresh baseDir
// (or one with nothing pulled yet) simply has nothing to prune there.
func candidateHashes(manifestsDir, layersDir string) ([]string, error) {
	seen := map[string]bool{}
	var hashes []string

	add := func(hash string) {
		if !seen[hash] {
			seen[hash] = true
			hashes = append(hashes, hash)
		}
	}

	manifestEntries, err := os.ReadDir(manifestsDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", manifestsDir, err)
	}
	for _, entry := range manifestEntries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		add(strings.TrimSuffix(entry.Name(), ".json"))
	}

	layerEntries, err := os.ReadDir(layersDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", layersDir, err)
	}
	for _, entry := range layerEntries {
		if !entry.IsDir() {
			continue
		}
		add(entry.Name())
	}

	return hashes, nil
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
