// Package build provides bookkeeping for an entire SBOM build, one level
// above internal/plugin's per-component manifests: recording the SBOM
// itself as the manifest for a build once every component it describes
// has been pulled, and a repositories.json mapping user-supplied tags to
// that manifest's hash — mirroring Docker's own on-disk repositories.json
// format (repo -> tag -> id).
package build

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
)

// RecordManifest hashes the SBOM at sbomPath and copies it verbatim to
// "<baseDir>/manifests/<hash>.json". If a manifest for that hash already
// exists, the SBOM has already been fully built, so RecordManifest skips
// the copy and reports skipped.
func RecordManifest(baseDir, sbomPath string) (sbomHash string, skipped bool, err error) {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return "", false, fmt.Errorf("read sbom %s: %w", sbomPath, err)
	}

	sum := sha256.Sum256(data)
	sbomHash = hex.EncodeToString(sum[:])

	path := layout.Manifest(baseDir, sbomHash)
	if _, err := os.Stat(path); err == nil {
		return sbomHash, true, nil
	} else if !os.IsNotExist(err) {
		return sbomHash, false, fmt.Errorf("stat %s: %w", path, err)
	}

	if err := fsutil.WriteFileAtomic(path, data); err != nil {
		return sbomHash, false, err
	}

	return sbomHash, false, nil
}

// Repositories is the "<baseDir>/package/repositories.json" record
// mapping tags to the aggregate SBOM manifest hash they resolve to:
// repo name -> tag/version -> sbom hash.
type Repositories map[string]map[string]string

// ReadRepositories reads and parses baseDir's repositories.json,
// returning an empty Repositories if it doesn't exist yet.
func ReadRepositories(baseDir string) (Repositories, error) {
	repos := Repositories{}
	if err := fsutil.ReadJSON(layout.Repositories(baseDir), &repos); err != nil {
		return nil, err
	}
	return repos, nil
}

// ResolveTag looks up tag's sbom hash in "<baseDir>/package/repositories.json",
// returning an error if the repository or version isn't recorded there.
func ResolveTag(baseDir, tag string) (string, error) {
	repos, err := ReadRepositories(baseDir)
	if err != nil {
		return "", err
	}

	repo, version := splitTag(tag)
	versions, ok := repos[repo]
	if !ok {
		return "", fmt.Errorf("no such package: %s", tag)
	}

	sbomHash, ok := versions[version]
	if !ok {
		return "", fmt.Errorf("no such package: %s", tag)
	}

	return sbomHash, nil
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

	repos, err := ReadRepositories(baseDir)
	if err != nil {
		return err
	}

	for _, tag := range tags {
		repo, version := splitTag(tag)
		if repos[repo] == nil {
			repos[repo] = map[string]string{}
		}
		repos[repo][version] = sbomHash
	}

	return writeRepositories(baseDir, repos)
}

// RemoveTag removes tag's mapping from
// "<baseDir>/package/repositories.json", returning an error if tag isn't
// currently mapped to anything. RemoveTag only removes the tag itself —
// reclaiming the manifest and any components this was the last tag for
// is Prune's job, not RemoveTag's.
func RemoveTag(baseDir, tag string) error {
	repos, err := ReadRepositories(baseDir)
	if err != nil {
		return err
	}

	repo, version := splitTag(tag)
	versions, ok := repos[repo]
	if !ok {
		return fmt.Errorf("no such tag: %s", tag)
	}
	if _, ok := versions[version]; !ok {
		return fmt.Errorf("no such tag: %s", tag)
	}

	delete(versions, version)
	if len(versions) == 0 {
		delete(repos, repo)
	}

	return writeRepositories(baseDir, repos)
}

// writeRepositories writes repos to baseDir's repositories.json.
func writeRepositories(baseDir string, repos Repositories) error {
	return fsutil.WriteJSON(layout.Repositories(baseDir), repos)
}

// splitTag splits "name:version" into its repo and version parts,
// defaulting version to "latest" when tag has none.
func splitTag(tag string) (repo, version string) {
	if i := strings.LastIndex(tag, ":"); i >= 0 {
		return tag[:i], tag[i+1:]
	}
	return tag, "latest"
}
