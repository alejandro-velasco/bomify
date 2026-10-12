package pull

import (
	"context"
	"errors"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
)

// PackageComponent is one component of a package in a registry, with
// what carries its files there.
type PackageComponent struct {
	Component cdx.Component
	// Layers is how many of the package's layers carry its files, and Size
	// how many bytes those take in the registry.
	Layers int
	Size   int64
}

// Components resolves ref against target and lists the components its SBOM
// describes, in the SBOM's order. Like Manifest, it touches no data
// directory, and it verifies nothing: PullComponent does, before it
// fetches a file.
func Components(ctx context.Context, target oras.ReadOnlyTarget, ref string) ([]PackageComponent, error) {
	manifest, data, err := fetchManifestAndSBOM(ctx, target, ref)
	if err != nil {
		return nil, err
	}
	bom, err := sbom.LoadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("parse sbom manifest %s: %w", manifest.Config.Digest, err)
	}
	return packageComponents(bom, manifest.Layers), nil
}

// packageComponents pairs each component of bom with the layers, of a
// package's, that name its purl.
func packageComponents(bom *cdx.BOM, layers []ocispec.Descriptor) []PackageComponent {
	components := sliceutil.Deref(bom.Components)
	listed := make([]PackageComponent, 0, len(components))
	for _, component := range components {
		entry := PackageComponent{Component: component}
		for _, layer := range componentLayers(layers, component.PackageURL) {
			entry.Layers++
			entry.Size += layer.Size
		}
		listed = append(listed, entry)
	}
	return listed
}

// componentLayers returns the layers of descs that name purl, none for
// an empty one.
func componentLayers(descs []ocispec.Descriptor, purl string) []ocispec.Descriptor {
	if purl == "" {
		return nil
	}
	var named []ocispec.Descriptor
	for _, desc := range descs {
		if desc.Annotations[transfer.AnnotationPurl] == purl {
			named = append(named, desc)
		}
	}
	return named
}

// The errors for a component selector that names no component of a
// package, and one that names several. Neither lists the package's
// components, which may be many.
var (
	ErrNoComponent        = errors.New("no such component in the package")
	ErrAmbiguousComponent = errors.New("names several components in the package; name one by its purl")
)

// selectComponent returns the one of components that selector names: its
// purl, else its name, alone or as <name>@<version>; else
// ErrAmbiguousComponent or ErrNoComponent.
func selectComponent(components []PackageComponent, selector string) (PackageComponent, error) {
	var named []PackageComponent
	for _, candidate := range components {
		component := candidate.Component
		if component.PackageURL == selector {
			return candidate, nil
		}
		if component.Name == selector || component.Name+"@"+component.Version == selector {
			named = append(named, candidate)
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(named) > 1 {
		return PackageComponent{}, fmt.Errorf("%q %w", selector, ErrAmbiguousComponent)
	}
	return PackageComponent{}, fmt.Errorf("%q: %w", selector, ErrNoComponent)
}

// ComponentResult is what PullComponent restored.
type ComponentResult struct {
	// ManifestDigest is the digest of the package manifest ref resolved
	// to, the one verified, as "sha256:...".
	ManifestDigest string
	// Component is the component restored, and Dir the directory its files
	// are in.
	Component cdx.Component
	Dir       string
	// Layers is how many layers its files came from.
	Layers int
}

// ComponentOptions are where PullComponent writes.
type ComponentOptions struct {
	// Dir is the directory the component's files go into. It must be
	// missing or empty, unless Replace is set (see writeInto).
	Dir     string
	Replace bool
}

// PullComponent restores the files of the one component of ref's package
// that selector names (see selectComponent) into into.Dir. It's
// PullLayers, keeping only that component's layers, into a scratch data
// directory inside into.Dir, from which the component's files move up into
// it: so verification, the download, and the checks on what's unpacked are
// Pull's, and the rest of the scratch data directory is thrown away.
// Nothing is recorded in the real data directory. into.Dir is left as it
// was if the pull fails.
func PullComponent(ctx context.Context, target oras.ReadOnlyTarget, ref, selector string, into ComponentOptions, opts transfer.Options) (ComponentResult, error) {
	components, err := Components(ctx, target, ref)
	if err != nil {
		return ComponentResult{}, err
	}
	selected, err := selectComponent(components, selector)
	if err != nil {
		return ComponentResult{}, err
	}
	purl := selected.Component.PackageURL
	if purl == "" {
		return ComponentResult{}, fmt.Errorf("component %q has no purl, so no layer can name it", selector)
	}
	if selected.Layers == 0 {
		return ComponentResult{}, fmt.Errorf("%s has no files in this package", purl)
	}

	keep := func(layerPurl string) bool { return layerPurl == purl }
	var pulled Result
	pullInto := func(stageDir string) (string, error) {
		var err error
		if pulled, err = PullLayers(ctx, target, ref, stageDir, opts, keep); err != nil {
			return "", err
		}
		return restoredDir(pulled, stageDir, purl)
	}
	if err := writeInto(into.Dir, into.Replace, pullInto); err != nil {
		return ComponentResult{}, err
	}

	result := ComponentResult{
		ManifestDigest: pulled.ManifestDigest,
		Component:      selected.Component,
		Dir:            into.Dir,
		Layers:         countLayers(pulled, purl),
	}
	return result, nil
}

// restoredDir returns the directory, under dataDir, Pull restored purl's
// files to, and fails unless every one of its layers went there: one
// bomify can't unpack is written as-is somewhere else (see fetchLayer),
// and a package whose verified manifest has none for purl, e.g. because
// its tag moved since the component was listed, restored nothing.
func restoredDir(pulled Result, dataDir, purl string) (string, error) {
	dir := layout.ComponentLayer(dataDir, purl)
	if countLayers(pulled, purl) == 0 {
		return "", fmt.Errorf("%s has no files in this package", purl)
	}
	for _, layer := range pulled.Layers {
		if layer.Purl == purl && layer.Path != dir {
			return "", fmt.Errorf("%s has a layer, %s, that isn't in bomify's own format, so it can't be unpacked", purl, layer.Hash)
		}
	}
	return dir, nil
}

// countLayers counts the layers of pulled that are purl's.
func countLayers(pulled Result, purl string) int {
	count := 0
	for _, layer := range pulled.Layers {
		if layer.Purl == purl {
			count++
		}
	}
	return count
}
