// Package install installs plugins from bomify packages: a package whose
// SBOM describes one or more plugin.PurlType components — a plugin
// binary each, typically one per OS/architecture — is pulled like any
// other package, and the binaries built for this machine are placed in
// the plugins directory (see plugin.Dir), the only place bomify looks
// for them.
package install

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

// indexFile is the name of the record of installed plugins, inside the
// plugins directory.
const indexFile = "installed.json"

// Record describes one plugin "bomify plugin install" installed.
type Record struct {
	// Kind is the plugin's kind: it's installed as bomify-plugin-<Kind>.
	Kind string `json:"kind"`
	// Version is its purl's version, if it declared one.
	Version string `json:"version,omitempty"`
	// Reference is the package it was installed from.
	Reference string `json:"reference"`
	// SHA256 is the installed binary's SHA-256, hex-encoded.
	SHA256 string `json:"sha256"`
}

// Options configure Install.
type Options struct {
	// Concurrency bounds how many layers download at once.
	Concurrency int
	// Progress reports download progress; nil discards it.
	Progress transfer.ProgressFunc
	// Verify, if non-nil, must accept the package's manifest before
	// anything is downloaded (see pull.Pull).
	Verify transfer.Verifier
	// RequireChecksum fails the install of any binary whose component
	// doesn't declare a SHA-256 hash to check it against. A declared hash
	// is always checked, whether or not this is set.
	RequireChecksum bool
	// GOOS and GOARCH select which binaries to install; empty means the
	// running machine's.
	GOOS, GOARCH string
	// Logger receives progress logging; nil discards it.
	Logger *slog.Logger
}

// Install pulls the package ref names from target into a staging
// directory, picks every plugin.PurlType component its SBOM describes
// that matches opts.GOOS/opts.GOARCH, checks each binary against its
// component's declared SHA-256, and only then — every one having passed
// — moves them all into dataDir's plugins directory, replacing any
// earlier install of the same kind, and records them (see List). Nothing
// is installed if any step fails, and the staging directory is always
// removed again; the package itself is never recorded as a local package
// the way "bomify pull" would.
func Install(ctx context.Context, target oras.ReadOnlyTarget, ref, dataDir string, opts Options) ([]Record, error) {
	goos, goarch := opts.GOOS, opts.GOARCH
	if goos == "" {
		goos = hostOS
	}
	if goarch == "" {
		goarch = hostArch
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	dir := layout.Plugins(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create plugins directory: %w", err)
	}

	// Staged inside dir itself, so moving a binary into place is a rename
	// on the same filesystem rather than a copy.
	staging, err := os.MkdirTemp(dir, ".install-*")
	if err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	// A plugin package typically carries every platform's binary; only
	// download the ones this install could possibly use.
	keep := func(purl string) bool {
		b, ok, err := plugin.ParseBinary(cdx.Component{PackageURL: purl})
		return err == nil && ok && b.Matches(goos, goarch)
	}
	result, err := pull.PullLayers(ctx, target, ref, staging, transfer.Options{Concurrency: opts.Concurrency, Progress: opts.Progress, Verify: opts.Verify}, keep)
	if err != nil {
		return nil, err
	}

	bom, err := sbom.Load(layout.Manifest(staging, result.SBOMHash))
	if err != nil {
		return nil, fmt.Errorf("load package sbom: %w", err)
	}

	candidates, err := selectBinaries(bom, goos, goarch)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}

	type staged struct {
		src    string
		record Record
	}
	var ready []staged
	for _, c := range candidates {
		src := filepath.Join(layout.ComponentLayer(staging, c.component.PackageURL), c.binary.FileName())
		sum, err := verifyBinary(src, c.component, opts.RequireChecksum)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.component.PackageURL, err)
		}
		ready = append(ready, staged{src: src, record: Record{Kind: c.binary.Kind, Version: c.binary.Version, Reference: ref, SHA256: sum}})
	}

	index, err := readIndex(dir)
	if err != nil {
		return nil, err
	}

	records := make([]Record, 0, len(ready))
	for _, s := range ready {
		dst := filepath.Join(dir, plugin.ExecutableName(s.record.Kind, goos))
		if err := os.Chmod(s.src, 0o755); err != nil {
			return nil, fmt.Errorf("make %s executable: %w", s.src, err)
		}
		if err := os.Rename(s.src, dst); err != nil {
			return nil, fmt.Errorf("install %s: %w", dst, err)
		}
		logger.Info("plugin installed", "kind", s.record.Kind, "version", s.record.Version, "path", dst, "sha256", s.record.SHA256)

		index[s.record.Kind] = s.record
		records = append(records, s.record)
	}

	if err := writeIndex(dir, index); err != nil {
		return nil, err
	}

	return records, nil
}

// candidate is one plugin binary component selected for install.
type candidate struct {
	component cdx.Component
	binary    plugin.Binary
}

// selectBinaries picks bom's plugin.PurlType components that run on
// goos/goarch — at most one per kind — failing if there are none.
func selectBinaries(bom *cdx.BOM, goos, goarch string) ([]candidate, error) {
	var selected []candidate
	seen := map[string]bool{}
	var platforms []string

	if bom.Components != nil {
		for _, component := range *bom.Components {
			b, ok, err := plugin.ParseBinary(component)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			platforms = append(platforms, platformOf(b))
			if !b.Matches(goos, goarch) {
				continue
			}
			if seen[b.Kind] {
				return nil, fmt.Errorf("more than one bomify-plugin component for %q matches %s/%s", b.Kind, goos, goarch)
			}
			seen[b.Kind] = true
			selected = append(selected, candidate{component: component, binary: b})
		}
	}

	if len(selected) == 0 {
		if len(platforms) == 0 {
			return nil, fmt.Errorf("package describes no pkg:%s components", plugin.PurlType)
		}
		return nil, fmt.Errorf("package has no plugin binary for %s/%s (available: %s)", goos, goarch, strings.Join(platforms, ", "))
	}
	return selected, nil
}

// platformOf formats b's kind and platform for an error message.
func platformOf(b plugin.Binary) string {
	os, arch := b.OS, b.Arch
	if os == "" {
		os = "any"
	}
	if arch == "" {
		arch = "any"
	}
	return fmt.Sprintf("%s %s/%s", b.Kind, os, arch)
}

// verifyBinary checks the binary at src against the SHA-256 component
// declares, returning its actual SHA-256. A component declaring none
// fails only when required.
func verifyBinary(src string, component cdx.Component, required bool) (string, error) {
	sum, err := plugin.HashFile(src)
	if err != nil {
		return "", fmt.Errorf("plugin binary missing from package: %w", err)
	}

	declared := ""
	if component.Hashes != nil {
		for _, h := range *component.Hashes {
			if h.Algorithm == cdx.HashAlgoSHA256 {
				declared = h.Value
				break
			}
		}
	}

	switch {
	case declared == "" && required:
		return "", fmt.Errorf("the package's SBOM declares no %s hash to verify the plugin binary against (pass --verify=false to install it anyway)", cdx.HashAlgoSHA256)
	case declared != "" && !strings.EqualFold(declared, sum):
		return "", fmt.Errorf("%s mismatch: SBOM declares %s, plugin binary has %s", cdx.HashAlgoSHA256, declared, sum)
	}
	return sum, nil
}

// Entry is one plugin List found installed.
type Entry struct {
	// Kind is the plugin's kind (bomify-plugin-<Kind>).
	Kind string
	// Path is the installed binary.
	Path string
	// Record is how "bomify plugin install" installed it, or nil for a
	// binary placed in the plugins directory some other way (e.g. "make
	// install").
	Record *Record
}

// List reports every plugin installed in dataDir's plugins directory,
// sorted by kind: every bomify-plugin-<kind> executable there, with how
// it was installed when Install did it.
func List(dataDir string) ([]Entry, error) {
	dir := layout.Plugins(dataDir)

	files, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	index, err := readIndex(dir)
	if err != nil {
		return nil, err
	}

	var entries []Entry
	for _, f := range files {
		kind, ok := kindOf(f)
		if !ok {
			continue
		}
		entry := Entry{Kind: kind, Path: filepath.Join(dir, f.Name())}
		if record, ok := index[kind]; ok {
			entry.Record = &record
		}
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Kind < entries[j].Kind })
	return entries, nil
}

// kindOf returns the kind of the plugin binary f names, if it is one.
func kindOf(f fs.DirEntry) (string, bool) {
	if f.IsDir() {
		return "", false
	}
	name := f.Name()
	if hostOS == "windows" {
		var ok bool
		if name, ok = strings.CutSuffix(name, ".exe"); !ok {
			return "", false
		}
	}
	kind, ok := strings.CutPrefix(name, plugin.BinaryName(""))
	return kind, ok && kind != ""
}

// readIndex reads dir's record of installed plugins, keyed by kind,
// returning an empty one if there isn't one yet.
func readIndex(dir string) (map[string]Record, error) {
	index := map[string]Record{}
	if err := fsutil.ReadJSON(filepath.Join(dir, indexFile), &index); err != nil {
		return nil, err
	}
	return index, nil
}

// writeIndex atomically replaces dir's record of installed plugins.
func writeIndex(dir string, index map[string]Record) error {
	return fsutil.WriteJSON(filepath.Join(dir, indexFile), index)
}
