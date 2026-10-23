package pull

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
)

// PackageComponent is one component of a package in a registry.
type PackageComponent struct {
	Component cdx.Component
	// Files is its files, as the package's files map lays them out, or the
	// zero ComponentFiles if the map has none for it.
	Files transfer.ComponentFiles
	// Reference is where push tagged the component's own manifest (see
	// transfer.AnnotationComponentReference), resolved against the
	// package's repository, or "" if push tagged none.
	Reference string
	// Manifest is the component manifest's entry in the package's index,
	// or the zero descriptor if the index has none for it.
	Manifest ocispec.Descriptor
}

// Components resolves ref against target and lists the components its SBOM
// describes, in the SBOM's order. Like Manifest, it touches no data
// directory, and it verifies nothing: PullComponent does, before it
// fetches a file.
func Components(ctx context.Context, target oras.ReadOnlyTarget, ref string) ([]PackageComponent, error) {
	opts := transfer.Options{}.WithDefaults()
	pkg, err := fetchPackage(ctx, target, ref, opts)
	if err != nil {
		return nil, err
	}
	return pkg.listComponents(ref), nil
}

// VerifiedComponents is Components for a package verified as opts asks,
// as PullComponent verifies one, before anything else is fetched. It
// returns the digest of the index ref resolved to, the one verified.
func VerifiedComponents(ctx context.Context, target oras.ReadOnlyTarget, ref string, opts transfer.Options) (string, []PackageComponent, error) {
	pkg, err := fetchPackage(ctx, target, ref, opts.WithDefaults())
	if err != nil {
		return "", nil, err
	}
	return pkg.desc.Digest.String(), pkg.listComponents(ref), nil
}

// listComponents pairs each component of p's SBOM with its files in p's
// files map, and its reference, resolved against ref's repository.
func (p *fetchedPackage) listComponents(ref string) []PackageComponent {
	repository := prefix.Repository(ref)
	references := map[string]string{}
	manifests := map[string]ocispec.Descriptor{}
	for _, desc := range p.components {
		purl := desc.Annotations[transfer.AnnotationPurl]
		manifests[purl] = desc
		if reference := desc.Annotations[transfer.AnnotationComponentReference]; reference != "" {
			references[purl] = path.Join(repository, reference)
		}
	}

	components := sliceutil.Deref(p.sbom.bom.Components)
	listed := make([]PackageComponent, 0, len(components))
	for _, component := range components {
		files, _ := p.files.Component(component.PackageURL)
		entry := PackageComponent{
			Component: component,
			Files:     files,
			Reference: references[component.PackageURL],
			Manifest:  manifests[component.PackageURL],
		}
		listed = append(listed, entry)
	}
	return listed
}

// The errors for a component selector that names no component of a
// package, and one that names several. Neither lists the package's
// components, which may be many; an ambiguous selector's error lists the
// purls of just the ones it names.
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
		purls := make([]string, 0, len(named))
		for _, candidate := range named {
			purls = append(purls, candidate.Component.PackageURL)
		}
		return PackageComponent{}, fmt.Errorf("%q %w: %s", selector, ErrAmbiguousComponent, strings.Join(purls, ", "))
	}
	return PackageComponent{}, fmt.Errorf("%q: %w", selector, ErrNoComponent)
}

// ComponentResult is what PullComponent restored.
type ComponentResult struct {
	// ManifestDigest is the digest of the package index ref resolved to,
	// the one verified, as "sha256:...".
	ManifestDigest string
	// Component is the component restored, Dir the directory its files are
	// in, and Files how many there are.
	Component cdx.Component
	Dir       string
	Files     int
}

// ComponentOptions are where PullComponent writes.
type ComponentOptions struct {
	// Dir is the directory the component's files go into. It must be
	// missing or empty, unless Replace is set (see WriteInto).
	Dir     string
	Replace bool
}

// PullComponent restores the files of the one component of ref's package
// that selector names (see selectComponent) into into.Dir, from the
// package's files map, as Pull restores it into a data directory: the
// package is verified as opts asks before anything is fetched, and each
// file is checked against its digest. Nothing is written to a data
// directory, and into.Dir is left as it was if the pull fails.
func PullComponent(ctx context.Context, target oras.ReadOnlyTarget, ref, selector string, into ComponentOptions, opts transfer.Options) (ComponentResult, error) {
	opts = opts.WithDefaults()

	// Checked before anything is fetched too, so an unusable directory
	// fails fast.
	if err := CheckOutputDir(into.Dir, into.Replace); err != nil {
		return ComponentResult{}, err
	}
	pkg, err := fetchPackage(ctx, target, ref, opts)
	if err != nil {
		return ComponentResult{}, err
	}
	components := pkg.listComponents(ref)
	selected, err := selectComponent(components, selector)
	if err != nil {
		return ComponentResult{}, err
	}
	files := selected.Files
	if files.Purl == "" {
		return ComponentResult{}, fmt.Errorf("%q has no files in this package", selector)
	}

	restore := componentRestore{
		restoreOptions: newRestoreOptions(target, "", opts.Concurrency, opts.Progress),
		files:          files,
	}
	write := func(dir string) error { return restore.apply(ctx, dir) }
	if err := WriteInto(into.Dir, into.Replace, write); err != nil {
		return ComponentResult{}, fmt.Errorf("restore %s: %w", files.Purl, err)
	}

	result := ComponentResult{
		ManifestDigest: pkg.desc.Digest.String(),
		Component:      selected.Component,
		Dir:            into.Dir,
		Files:          len(files.Files),
	}
	return result, nil
}
