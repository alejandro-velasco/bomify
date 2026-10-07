package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// TreeHash returns a pulled repository's SHA-256 and the paths of its
// files, sorted. The hash is of the listing "sha256sum" prints for every
// file, sorted by path, so anyone can reproduce it without bomify:
//
//	cd <dir> && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --text | sha256sum
//
// Each line is "<file's SHA-256>  ./<path>\n", with "/" separating path
// segments. Only regular files may be in dir, and no path may contain a
// newline or backslash, which sha256sum would escape.
func TreeHash(dir string) (string, []string, error) {
	paths, err := localPaths(dir)
	if err != nil {
		return "", nil, err
	}
	hash, err := hashListing(paths, func(path string) (string, error) {
		return hashFile(filepath.Join(dir, filepath.FromSlash(path)))
	})
	return hash, paths, err
}

// hashListing returns the TreeHash of the files at paths, sorted, given
// each one's SHA-256 from fileHash: from disk after a pull, or from the
// Hub's listing when generating an SBOM.
func hashListing(paths []string, fileHash func(path string) (string, error)) (string, error) {
	listing := sha256.New()
	for _, path := range slices.Sorted(slices.Values(paths)) {
		hash, err := fileHash(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(listing, "%s  ./%s\n", hash, path)
	}
	return hex.EncodeToString(listing.Sum(nil)), nil
}

// localPaths returns the "/"-separated paths of every file in dir,
// sorted, failing on anything but regular files and directories, or a
// path with a newline or backslash.
func localPaths(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s isn't a regular file", relative)
		}
		if strings.ContainsAny(relative, "\n\\") {
			return fmt.Errorf("%q has a newline or backslash in its path", relative)
		}
		paths = append(paths, relative)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	sort.Strings(paths)
	return paths, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
