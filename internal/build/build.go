// Package build provides bookkeeping for an entire SBOM build, one level
// above internal/plugin's per-component manifests: recording the SBOM
// itself as the manifest for a build once every component it describes
// has been pulled, and a repositories.json mapping user-supplied tags to
// that manifest's hash — mirroring Docker's own on-disk repositories.json
// format (repo -> tag -> id).
package build

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestPath returns the deterministic path of the manifest for an SBOM
// with the given content hash (see RecordManifest).
func ManifestPath(baseDir, sbomHash string) string {
	return filepath.Join(baseDir, "manifests", sbomHash+".json")
}

// RecordManifest hashes the SBOM at sbomPath and, unless a manifest for
// that exact hash already exists — in which case it does nothing and
// reports skipped, since this exact SBOM has already been fully built —
// copies it verbatim to "<baseDir>/manifests/<hash>.json". The manifest
// is the original SBOM itself, not a derived summary, so that file is
// always the authoritative CycloneDX document for the build it records.
func RecordManifest(baseDir, sbomPath string) (sbomHash string, skipped bool, err error) {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return "", false, fmt.Errorf("read sbom %s: %w", sbomPath, err)
	}

	sum := sha256.Sum256(data)
	sbomHash = hex.EncodeToString(sum[:])

	path := ManifestPath(baseDir, sbomHash)
	if _, err := os.Stat(path); err == nil {
		return sbomHash, true, nil
	} else if !os.IsNotExist(err) {
		return sbomHash, false, fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return sbomHash, false, fmt.Errorf("create manifests directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return sbomHash, false, fmt.Errorf("write manifest %s: %w", path, err)
	}

	return sbomHash, false, nil
}

// Repositories is the "<baseDir>/package/repositories.json" record
// mapping tags to the aggregate SBOM manifest hash they resolve to:
// repo name -> tag/version -> sbom hash.
type Repositories map[string]map[string]string

// RepositoriesPath returns the deterministic path of baseDir's
// repositories.json.
func RepositoriesPath(baseDir string) string {
	return filepath.Join(baseDir, "package", "repositories.json")
}

// UpdateRepositories maps each of tags to sbomHash in
// "<baseDir>/package/repositories.json", merging into whatever is already
// there. A tag without a ":<version>" suffix defaults to version
// "latest", matching Docker's own tag convention. UpdateRepositories is a
// no-op if tags is empty.
func UpdateRepositories(baseDir string, tags []string, sbomHash string) error {
	if len(tags) == 0 {
		return nil
	}

	path := RepositoriesPath(baseDir)

	repos := Repositories{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &repos); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	for _, tag := range tags {
		repo, version := splitTag(tag)
		if repos[repo] == nil {
			repos[repo] = map[string]string{}
		}
		repos[repo][version] = sbomHash
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create package directory: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(repos); err != nil {
		return fmt.Errorf("marshal repositories: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

// splitTag splits "name:version" into its repo and version parts,
// defaulting version to "latest" when tag has none.
func splitTag(tag string) (repo, version string) {
	if i := strings.LastIndex(tag, ":"); i >= 0 {
		return tag[:i], tag[i+1:]
	}
	return tag, "latest"
}
