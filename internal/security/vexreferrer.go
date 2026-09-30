package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// VEXArtifactType identifies an OCI referrer of a bomify package
// carrying one VEX document its publisher attached (see AttachVEX).
const VEXArtifactType = "application/vnd.bomify.vex.v1+json"

// VEXDocumentMediaType identifies a VEX referrer's one layer: the
// document itself, in whichever format it was written (OpenVEX, CSAF, or
// CycloneDX VEX — LoadVEX tells them apart by content).
const VEXDocumentMediaType = "application/vnd.bomify.vex.document.v1"

// maxVEXDocumentSize bounds how large an attached VEX document
// FetchVEX will download: like signatures, attached VEX comes from
// whoever could push to the repository.
const maxVEXDocumentSize = 4 << 20

// VEXDocument is a VEX document's content and a name for it, as
// published with a package or restored from one.
type VEXDocument struct {
	// Name labels the document in logs and referrer annotations — a
	// stored name or a file name when published, the referrer's digest
	// when pulled. Informational only.
	Name string
	Data []byte
}

// AttachVEX attaches each of docs to the package manifest in target as
// its own VEX referrer — a manifest of VEXArtifactType whose subject is
// the package and whose one layer is the document — dated now. A
// document the package already carries (by content) is skipped, so
// pushing again with the same documents attaches nothing new. It returns
// the referrers it attached, for the caller to sign.
func AttachVEX(ctx context.Context, target oras.Target, manifest ocispec.Descriptor, docs []VEXDocument) ([]ocispec.Descriptor, error) {
	if len(docs) == 0 {
		return nil, nil
	}

	attached := map[string]bool{}
	if graph, ok := target.(content.ReadOnlyGraphStorage); ok {
		existing, err := registry.Referrers(ctx, graph, manifest, VEXArtifactType)
		if err != nil {
			return nil, fmt.Errorf("list VEX referrers of %s: %w", manifest.Digest, err)
		}
		for _, ref := range existing {
			if layers, err := vexLayers(ctx, graph, ref); err == nil {
				for _, l := range layers {
					attached[l.Digest.String()] = true
				}
			}
		}
	}

	configDesc, err := transfer.PushBytes(ctx, target, ocispec.DescriptorEmptyJSON.Data, ocispec.MediaTypeEmptyJSON, "empty config", nil)
	if err != nil {
		return nil, fmt.Errorf("push empty config: %w", err)
	}
	subject := ocispec.Descriptor{MediaType: manifest.MediaType, Digest: manifest.Digest, Size: manifest.Size}
	created := time.Now().UTC().Format(time.RFC3339)

	var referrers []ocispec.Descriptor
	for _, doc := range docs {
		layer, err := transfer.PushBytes(ctx, target, doc.Data, VEXDocumentMediaType, "VEX document: "+doc.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("push VEX document %s: %w", doc.Name, err)
		}
		if attached[layer.Digest.String()] {
			continue
		}
		attached[layer.Digest.String()] = true
		layer.Annotations = map[string]string{ocispec.AnnotationTitle: doc.Name}

		annotations := map[string]string{ocispec.AnnotationCreated: created}
		data, err := json.Marshal(ocispec.Manifest{
			Versioned:    specs.Versioned{SchemaVersion: 2},
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: VEXArtifactType,
			Config:       configDesc,
			Layers:       []ocispec.Descriptor{layer},
			Subject:      &subject,
			Annotations:  annotations,
		})
		if err != nil {
			return nil, fmt.Errorf("encode VEX referrer: %w", err)
		}
		referrer, err := transfer.PushBytes(ctx, target, data, ocispec.MediaTypeImageManifest, "VEX referrer: "+doc.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("push VEX referrer %s: %w", doc.Name, err)
		}
		referrer.ArtifactType = VEXArtifactType
		referrer.Annotations = annotations
		referrers = append(referrers, referrer)
	}
	return referrers, nil
}

// VEXReferrers lists manifest's VEX referrers in target, oldest first
// by their created annotation (ties broken by digest), so that applied
// in order, a later publication's statements win over an earlier one's.
// A target that can't list referrers has none.
func VEXReferrers(ctx context.Context, target content.ReadOnlyStorage, manifest ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	graph, ok := target.(content.ReadOnlyGraphStorage)
	if !ok {
		return nil, nil
	}
	referrers, err := registry.Referrers(ctx, graph, manifest, VEXArtifactType)
	if err != nil {
		return nil, fmt.Errorf("list VEX referrers of %s: %w", manifest.Digest, err)
	}
	referrers = slices.DeleteFunc(referrers, func(d ocispec.Descriptor) bool {
		return d.ArtifactType != VEXArtifactType
	})
	slices.SortStableFunc(referrers, func(a, b ocispec.Descriptor) int {
		if c := createdAt(a).Compare(createdAt(b)); c != 0 {
			return c
		}
		return strings.Compare(a.Digest.String(), b.Digest.String())
	})
	return referrers, nil
}

// FetchVEX downloads the one document a VEX referrer carries.
func FetchVEX(ctx context.Context, target content.ReadOnlyStorage, referrer ocispec.Descriptor) (VEXDocument, error) {
	layers, err := vexLayers(ctx, target, referrer)
	if err != nil {
		return VEXDocument{}, err
	}
	if len(layers) != 1 {
		return VEXDocument{}, fmt.Errorf("VEX referrer %s has %d documents, want exactly 1", referrer.Digest, len(layers))
	}
	if layers[0].Size > maxVEXDocumentSize {
		return VEXDocument{}, fmt.Errorf("VEX document in %s is %d bytes, larger than the %d allowed", referrer.Digest, layers[0].Size, maxVEXDocumentSize)
	}
	data, err := content.FetchAll(ctx, target, layers[0])
	if err != nil {
		return VEXDocument{}, fmt.Errorf("fetch VEX document in %s: %w", referrer.Digest, err)
	}
	return VEXDocument{Name: referrer.Digest.String(), Data: data}, nil
}

// vexLayers returns the VEX document layers of a VEX referrer.
func vexLayers(ctx context.Context, target content.ReadOnlyStorage, referrer ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	if referrer.Size > maxReferrerManifestSize {
		return nil, fmt.Errorf("referrer %s is %d bytes, larger than the %d allowed", referrer.Digest, referrer.Size, maxReferrerManifestSize)
	}
	data, err := content.FetchAll(ctx, target, referrer)
	if err != nil {
		return nil, fmt.Errorf("fetch referrer %s: %w", referrer.Digest, err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse referrer %s: %w", referrer.Digest, err)
	}
	return slices.DeleteFunc(m.Layers, func(d ocispec.Descriptor) bool {
		return d.MediaType != VEXDocumentMediaType
	}), nil
}

// LoadVEXDocuments is LoadVEX for documents held in memory — e.g.
// fetched from a package — each labeled source+its Name in exemption
// logs.
func LoadVEXDocuments(docs []VEXDocument, source string) (*VEX, error) {
	if len(docs) == 0 {
		return nil, nil
	}
	dir, err := os.MkdirTemp("", "bomify-vex-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	v := &VEX{}
	for i, doc := range docs {
		path := filepath.Join(dir, fmt.Sprintf("%d.vex", i))
		if err := os.WriteFile(path, doc.Data, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", doc.Name, err)
		}
		statements, err := loadStatements(path)
		if err != nil {
			return nil, fmt.Errorf("load VEX %s: %w", doc.Name, err)
		}
		for _, s := range statements {
			v.statements = append(v.statements, SourcedStatement{Statement: s, Source: source + doc.Name})
		}
	}
	return v, nil
}

// CombineVEX returns the statements of first and then of then, so that
// where they disagree then's win (see VEX.exempts). Either may be nil.
func CombineVEX(first, then *VEX) *VEX {
	if first == nil {
		return then
	}
	if then == nil {
		return first
	}
	return &VEX{statements: append(slices.Clone(first.statements), then.statements...)}
}
