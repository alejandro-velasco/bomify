package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
)

// maxReferrerManifestSize and maxReferrerLayerSize bound what bomify
// reads from a referrer. Referrers are published by whoever could push to
// the repository, not necessarily whoever bomify trusts, so these keep a
// hostile one from making bomify download something arbitrarily large.
const (
	maxReferrerManifestSize = 4 << 20
	maxReferrerLayerSize    = 4 << 20
)

// PushReferrer pushes an OCI 1.1 referrer of subject into target: a
// manifest of artifactType, with an empty config, whose layers (already
// in target) are layers. label names it in errors. Pushing an identical
// referrer again leaves the existing one alone (see PushBytes), so a
// referrer built only from its content is idempotent.
func PushReferrer(ctx context.Context, target oras.Target, subject ocispec.Descriptor, artifactType string, layers []ocispec.Descriptor, annotations map[string]string, label string) (ocispec.Descriptor, error) {
	config, err := PushBytes(ctx, target, ocispec.DescriptorEmptyJSON.Data, ocispec.MediaTypeEmptyJSON, "empty config", nil)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push empty config: %w", err)
	}

	subject = ocispec.Descriptor{MediaType: subject.MediaType, Digest: subject.Digest, Size: subject.Size}
	data, err := json.Marshal(ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       config,
		Layers:       layers,
		Subject:      &subject,
		Annotations:  annotations,
	})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("encode %s referrer: %w", label, err)
	}

	referrer, err := PushBytes(ctx, target, data, ocispec.MediaTypeImageManifest, label, nil)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push %s referrer: %w", label, err)
	}
	referrer.ArtifactType = artifactType
	referrer.Annotations = annotations
	return referrer, nil
}

// Referrers lists subject's referrers of artifactType in target, newest
// first by their created annotation (ties broken by digest, so the order
// is stable). A target that can't list referrers at all is an error.
func Referrers(ctx context.Context, target content.ReadOnlyStorage, subject ocispec.Descriptor, artifactType string) ([]ocispec.Descriptor, error) {
	graph, ok := target.(content.ReadOnlyGraphStorage)
	if !ok {
		return nil, fmt.Errorf("cannot list referrers: %T does not support them", target)
	}

	referrers, err := registry.Referrers(ctx, graph, subject, artifactType)
	if err != nil {
		return nil, fmt.Errorf("list %s referrers of %s: %w", artifactType, subject.Digest, err)
	}
	// A registry's Referrers API may ignore the artifactType filter.
	referrers = slices.DeleteFunc(referrers, func(d ocispec.Descriptor) bool {
		return d.ArtifactType != artifactType
	})

	slices.SortStableFunc(referrers, func(a, b ocispec.Descriptor) int {
		if c := createdAt(b).Compare(createdAt(a)); c != 0 {
			return c
		}
		return strings.Compare(b.Digest.String(), a.Digest.String())
	})
	return referrers, nil
}

func createdAt(desc ocispec.Descriptor) time.Time {
	t, _ := time.Parse(time.RFC3339, desc.Annotations[ocispec.AnnotationCreated])
	return t
}

// ReferrerLayers returns referrer's layers of mediaType.
func ReferrerLayers(ctx context.Context, target content.ReadOnlyStorage, referrer ocispec.Descriptor, mediaType string) ([]ocispec.Descriptor, error) {
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
		return d.MediaType != mediaType
	}), nil
}

// Attachment is a document Push attaches to a package as a referrer of
// its own — an artifact of ArtifactType whose one layer, of MediaType, is
// Data — and signs like the package.
type Attachment struct {
	ArtifactType string
	MediaType    string
	// Name labels the document: its layer's title annotation, and its
	// progress bar. Informational only.
	Name string
	Data []byte
}

// Attach attaches a to the package manifest in target, dated now, unless
// the package already carries a referrer of a.ArtifactType with the very
// same document — so attaching the same document again adds nothing.
// attached reports whether a new referrer was pushed.
func Attach(ctx context.Context, target oras.Target, manifest ocispec.Descriptor, a Attachment, progress ProgressFunc) (referrer ocispec.Descriptor, attached bool, err error) {
	layer, err := PushBytes(ctx, target, a.Data, a.MediaType, a.Name, progress)
	if err != nil {
		return ocispec.Descriptor{}, false, fmt.Errorf("push %s: %w", a.Name, err)
	}

	existing, err := Referrers(ctx, target, manifest, a.ArtifactType)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	for _, r := range existing {
		layers, err := ReferrerLayers(ctx, target, r, a.MediaType)
		if err != nil {
			return ocispec.Descriptor{}, false, err
		}
		if slices.ContainsFunc(layers, func(l ocispec.Descriptor) bool { return l.Digest == layer.Digest }) {
			return r, false, nil
		}
	}

	layer.Annotations = map[string]string{ocispec.AnnotationTitle: a.Name}
	// To the nanosecond, so documents attached in one push stay in order.
	annotations := map[string]string{ocispec.AnnotationCreated: time.Now().UTC().Format(time.RFC3339Nano)}
	referrer, err = PushReferrer(ctx, target, manifest, a.ArtifactType, []ocispec.Descriptor{layer}, annotations, a.Name)
	if err != nil {
		return ocispec.Descriptor{}, false, err
	}
	return referrer, true, nil
}

// FetchAttachment returns the one document an Attach referrer of
// mediaType carries.
func FetchAttachment(ctx context.Context, target content.ReadOnlyStorage, referrer ocispec.Descriptor, mediaType string) ([]byte, error) {
	layers, err := ReferrerLayers(ctx, target, referrer, mediaType)
	if err != nil {
		return nil, err
	}
	if len(layers) != 1 {
		return nil, fmt.Errorf("referrer %s has %d %s layers, want exactly 1", referrer.Digest, len(layers), mediaType)
	}
	if layers[0].Size > maxReferrerLayerSize {
		return nil, fmt.Errorf("layer of %s is %d bytes, larger than the %d allowed", referrer.Digest, layers[0].Size, maxReferrerLayerSize)
	}
	data, err := content.FetchAll(ctx, target, layers[0])
	if err != nil {
		return nil, fmt.Errorf("fetch layer of %s: %w", referrer.Digest, err)
	}
	return data, nil
}
