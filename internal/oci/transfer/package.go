package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
)

// A bomify package is an OCI image index of ArtifactType: its SBOM's
// manifest (see SBOMArtifactType), then each component's own manifest, in
// its kind's registry format where it has one (an image, a Helm chart, a
// ModelPack model), annotated on the index with its purl. Everything is in
// one repository, so any OCI tool that copies the index copies all of it.
const (
	// SBOMArtifactType identifies the package's SBOM manifest: its config
	// is the SBOM, and its layers the files map (see FilesMediaType), then
	// the extra files it names.
	SBOMArtifactType = "application/vnd.bomify.sbom.v1+json"
	// ComponentArtifactType identifies a component manifest in bomify's
	// own format, for a kind with none: an empty config, and each of the
	// component's files as a layer (see FileMediaType), by path, titled
	// with its path, so `oras pull` writes the component out as it is.
	ComponentArtifactType = "application/vnd.bomify.component.v1+json"
	// FileMediaType identifies a blob that is one of a component's files,
	// its own bytes: each layer of a component in bomify's own format, and
	// each extra file of the SBOM manifest (see Files). A file is never
	// split, so one past a registry's layer limit (10 GB on GHCR and Docker
	// Hub) can't be pushed there.
	FileMediaType = "application/vnd.bomify.component.file.v1"
	// FilesMediaType identifies the SBOM manifest's first layer, the files
	// map (see Files).
	FilesMediaType = "application/vnd.bomify.files.v1+json"
	// AnnotationComponentReference, on a component's index entry, is where
	// push tags the component's manifest beside the package, relative to
	// the package's repository: "<path>:<tag>", or "<path>@<digest>" for
	// an image pinned by digest alone, under which it's published untagged.
	// It's relative, so the index is the same wherever the package is.
	AnnotationComponentReference = "land.bomify.component.reference"
)

// ManifestMediaTypes are the media types a registry stores as a manifest
// rather than a blob: OCI's and Docker's manifests and indexes.
var ManifestMediaTypes = []string{
	ocispec.MediaTypeImageManifest,
	ocispec.MediaTypeImageIndex,
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}

// maxManifestSize bounds a manifest or index read from a package, as
// referrers are bounded.
const maxManifestSize = 4 << 20

// maxFilesSize bounds the files map read from a package: an entry per
// file of every component restored from it.
const maxFilesSize = 16 << 20

// Package is a bomify package, as its index lays it out.
type Package struct {
	// Index is the package's index.
	Index ocispec.Index
	// SBOM is the descriptor of the package's SBOM manifest, and
	// SBOMManifest the manifest.
	SBOM         ocispec.Descriptor
	SBOMManifest ocispec.Manifest
	// Components are the index's component manifests, each annotated with
	// its purl (see AnnotationPurl), in the index's order.
	Components []ocispec.Descriptor
}

// FetchPackage fetches the bomify package whose index desc names from
// target, and its SBOM manifest, failing unless desc is a bomify package's
// index with exactly one SBOM manifest. Index entries that are neither the
// SBOM manifest nor annotated with a purl are ignored.
func FetchPackage(ctx context.Context, target content.Fetcher, desc ocispec.Descriptor) (*Package, error) {
	if desc.MediaType != ocispec.MediaTypeImageIndex {
		return nil, fmt.Errorf("%s isn't a bomify package: it's a %s, not an index", desc.Digest, desc.MediaType)
	}
	var index ocispec.Index
	if err := fetchJSON(ctx, target, desc, maxManifestSize, &index); err != nil {
		return nil, fmt.Errorf("fetch index %s: %w", desc.Digest, err)
	}
	if index.ArtifactType != ArtifactType {
		return nil, fmt.Errorf("%s isn't a bomify package (artifact type %q)", desc.Digest, index.ArtifactType)
	}

	pkg := Package{Index: index}
	for _, entry := range index.Manifests {
		if entry.ArtifactType == SBOMArtifactType {
			if pkg.SBOM.Digest != "" {
				return nil, fmt.Errorf("package %s has more than one SBOM manifest", desc.Digest)
			}
			pkg.SBOM = entry
			continue
		}
		if entry.Annotations[AnnotationPurl] != "" {
			pkg.Components = append(pkg.Components, entry)
		}
	}
	if pkg.SBOM.Digest == "" {
		return nil, fmt.Errorf("package %s has no SBOM manifest", desc.Digest)
	}
	if err := fetchJSON(ctx, target, pkg.SBOM, maxManifestSize, &pkg.SBOMManifest); err != nil {
		return nil, fmt.Errorf("fetch SBOM manifest %s: %w", pkg.SBOM.Digest, err)
	}
	return &pkg, nil
}

// Files is a package's files map, its SBOM manifest's first layer: for
// each component, which blob in the package holds each of its files, which
// pull restores it from. A file is a blob of its component's artifact: a
// layer of bomify's own format or of a ModelPack model, or, in its kind's
// registry format, such as an image's layer in the OCI image layout it was
// pulled as. A file the format has no place for is a layer of the SBOM
// manifest instead.
type Files struct {
	Components []ComponentFiles `json:"components"`
}

// ComponentFiles is the files of one component, by purl, sorted by path.
type ComponentFiles struct {
	Purl  string     `json:"purl"`
	Files []FileBlob `json:"files"`
}

// Size returns how many bytes c's files take.
func (c ComponentFiles) Size() int64 {
	var size int64
	for _, file := range c.Files {
		size += file.Size
	}
	return size
}

// FileBlob is one file of a component: its "/"-separated path in the
// component's directory and permission bits, and the descriptor of the
// blob holding exactly its bytes.
type FileBlob struct {
	Path      string        `json:"path"`
	Mode      FileMode      `json:"mode"`
	MediaType string        `json:"mediaType"`
	Digest    digest.Digest `json:"digest"`
	Size      int64         `json:"size"`
}

// NewFileBlob returns the file at path, of mode's permission bits, held
// by the blob desc names.
func NewFileBlob(path string, mode fs.FileMode, desc ocispec.Descriptor) FileBlob {
	blob := FileBlob{
		Path:      path,
		Mode:      FileMode(mode.Perm()),
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
	return blob
}

// FileMode is a file's permission bits, in JSON an octal string, e.g.
// "0644".
type FileMode fs.FileMode

func (m FileMode) MarshalJSON() ([]byte, error) {
	octal := fmt.Sprintf("%04o", uint32(m))
	return json.Marshal(octal)
}

// UnmarshalJSON reads m, which comes from the network, failing on
// anything but permission bits.
func (m *FileMode) UnmarshalJSON(data []byte) error {
	var octal string
	if err := json.Unmarshal(data, &octal); err != nil {
		return err
	}
	bits, err := strconv.ParseUint(octal, 8, 32)
	if err != nil || bits > uint64(fs.ModePerm) {
		return fmt.Errorf("invalid file mode %q", octal)
	}
	*m = FileMode(bits)
	return nil
}

// Descriptor returns the descriptor of the blob holding b's bytes.
func (b FileBlob) Descriptor() ocispec.Descriptor {
	desc := ocispec.Descriptor{
		MediaType: b.MediaType,
		Digest:    b.Digest,
		Size:      b.Size,
	}
	return desc
}

// Component returns the files of the component purl names, if f has them.
func (f Files) Component(purl string) (ComponentFiles, bool) {
	index := slices.IndexFunc(f.Components, func(c ComponentFiles) bool { return c.Purl == purl })
	if index < 0 {
		return ComponentFiles{}, false
	}
	return f.Components[index], true
}

// FetchFiles fetches pkg's files map, failing unless it's the SBOM
// manifest's first layer and names each component once, and each of its
// files once, inside its component (see isSafePath), with a valid mode
// and a sha256 digest.
func FetchFiles(ctx context.Context, target content.Fetcher, pkg *Package) (Files, error) {
	layers := pkg.SBOMManifest.Layers
	if len(layers) == 0 || layers[0].MediaType != FilesMediaType {
		return Files{}, fmt.Errorf("SBOM manifest %s has no files map", pkg.SBOM.Digest)
	}
	var files Files
	if err := fetchJSON(ctx, target, layers[0], maxFilesSize, &files); err != nil {
		return Files{}, fmt.Errorf("fetch files map %s: %w", layers[0].Digest, err)
	}

	purls := map[string]bool{}
	for _, component := range files.Components {
		if component.Purl == "" || purls[component.Purl] {
			return Files{}, fmt.Errorf("files map names component %q more than once, or without a purl", component.Purl)
		}
		purls[component.Purl] = true
		paths := map[string]bool{}
		for _, file := range component.Files {
			if !isSafePath(file.Path) {
				return Files{}, fmt.Errorf("files map: %q of %s is outside its component", file.Path, component.Purl)
			}
			if paths[file.Path] {
				return Files{}, fmt.Errorf("files map names %s of %s more than once", file.Path, component.Purl)
			}
			paths[file.Path] = true
			if err := file.Digest.Validate(); err != nil || file.Digest.Algorithm() != digest.SHA256 {
				return Files{}, fmt.Errorf("files map: %s of %s: digest %q isn't sha256", file.Path, component.Purl, file.Digest)
			}
		}
	}
	return files, nil
}

// isSafePath reports whether path, "/"-separated and from the network,
// names a file inside the directory it's joined to: relative, with no
// ".." segment, no backslash, and no NUL byte.
func isSafePath(path string) bool {
	if path == "" || strings.ContainsAny(path, "\\\x00") {
		return false
	}
	return filepath.IsLocal(filepath.FromSlash(path))
}

// fetchJSON fetches desc, no more than limit bytes, from target, checked
// against its digest, and parses it into v.
func fetchJSON(ctx context.Context, target content.Fetcher, desc ocispec.Descriptor, limit int64, v any) error {
	if desc.Size > limit {
		return fmt.Errorf("%d bytes, larger than the %d allowed", desc.Size, limit)
	}
	data, err := content.FetchAll(ctx, target, desc)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	return nil
}
