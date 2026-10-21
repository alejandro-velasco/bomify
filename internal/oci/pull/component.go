package pull

import (
	"context"
	"errors"
	"fmt"
	"path"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	"github.com/alejandro-velasco/bomify/internal/sliceutil"
)

// PackageComponent is one component of a package in a registry.
type PackageComponent struct {
	Component cdx.Component
	// Files is how many files the package's files map lays out for it, and
	// Size how many bytes they take.
	Files int
	Size  int64
	// Reference is where push tagged the component's own manifest (see
	// transfer.AnnotationComponentReference), resolved against the
	// package's repository, or "" if push tagged none.
	Reference string
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

// listComponents pairs each component of p's SBOM with its files in p's
// files map, and its reference, resolved against ref's repository.
func (p *fetchedPackage) listComponents(ref string) []PackageComponent {
	repository := prefix.Repository(ref)
	references := map[string]string{}
	for _, desc := range p.components {
		if reference := desc.Annotations[transfer.AnnotationComponentReference]; reference != "" {
			references[desc.Annotations[transfer.AnnotationPurl]] = path.Join(repository, reference)
		}
	}

	components := sliceutil.Deref(p.sbom.bom.Components)
	listed := make([]PackageComponent, 0, len(components))
	for _, component := range components {
		entry := PackageComponent{
			Component: component,
			Reference: references[component.PackageURL],
		}
		files, _ := p.files.Component(component.PackageURL)
		for _, file := range files.Files {
			entry.Files++
			entry.Size += file.Size
		}
		listed = append(listed, entry)
	}
	return listed
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
	// missing or empty, unless Replace is set (see writeInto).
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
	if err := checkOutputDir(into.Dir, into.Replace); err != nil {
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
	purl := selected.Component.PackageURL
	files, ok := pkg.files.Component(purl)
	if !ok {
		return ComponentResult{}, fmt.Errorf("%q has no files in this package", selector)
	}

	restore := componentRestore{
		restoreOptions: newRestoreOptions(target, "", opts.Concurrency, opts.Progress),
		files:          files,
	}
	write := func(dir string) error { return restore.apply(ctx, dir) }
	if err := writeInto(into.Dir, into.Replace, write); err != nil {
		return ComponentResult{}, fmt.Errorf("restore %s: %w", purl, err)
	}

	result := ComponentResult{
		ManifestDigest: pkg.desc.Digest.String(),
		Component:      selected.Component,
		Dir:            into.Dir,
		Files:          len(files.Files),
	}
	return result, nil
}
