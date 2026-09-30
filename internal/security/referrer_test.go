package security

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

var testComponent = cdx.Component{
	Type:       cdx.ComponentTypeLibrary,
	Name:       "lib",
	Version:    "1.0",
	PackageURL: "pkg:generic/lib@1.0?download_url=https://example.com/lib",
}

// pruneFixture is a package manifest in an oci.Store carrying three
// signed report referrers (oldest first), a package signature, and an
// unrelated referrer some other tool attached.
type pruneFixture struct {
	store     *oci.Store
	manifest  ocispec.Descriptor
	reports   []ocispec.Descriptor
	reportSig []ocispec.Descriptor
	pkgSig    ocispec.Descriptor
	foreign   ocispec.Descriptor
}

func newPruneFixture(t *testing.T) pruneFixture {
	t.Helper()
	ctx := context.Background()

	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	f := pruneFixture{store: store}

	f.manifest, err = oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, transfer.ArtifactType, oras.PackManifestOptions{})
	if err != nil {
		t.Fatalf("pack package manifest: %v", err)
	}
	f.pkgSig = attachReferrer(t, store, f.manifest, "application/vnd.test.signature", "pkg")
	f.foreign = attachReferrer(t, store, f.manifest, "application/vnd.other.tool", "foreign")

	baseDir := t.TempDir()
	for i := range 3 {
		scannedAt := time.Date(2026, time.Month(i+1), 1, 0, 0, 0, 0, time.UTC)
		report := NewReport(testComponent, pluginlib.SecurityResult{Vulnerabilities: []cdx.Vulnerability{{ID: fmt.Sprintf("CVE-%d", i)}}}, "grype", scannedAt)
		if _, err := WriteReport(baseDir, testComponent, report); err != nil {
			t.Fatalf("WriteReport: %v", err)
		}
		referrer, _, ok, err := Attach(ctx, store, f.manifest, baseDir, []cdx.Component{testComponent}, nil)
		if err != nil || !ok {
			t.Fatalf("Attach() = %v, %v", ok, err)
		}
		f.reports = append(f.reports, referrer)
		f.reportSig = append(f.reportSig, attachReferrer(t, store, referrer, "application/vnd.test.signature", fmt.Sprintf("report-%d", i)))
	}
	return f
}

// attachReferrer packs a referrer of subject with the given artifact
// type, made distinct by name.
func attachReferrer(t *testing.T, target oras.Target, subject ocispec.Descriptor, artifactType, name string) ocispec.Descriptor {
	t.Helper()
	s := ocispec.Descriptor{MediaType: subject.MediaType, Digest: subject.Digest, Size: subject.Size}
	desc, err := oras.PackManifest(context.Background(), target, oras.PackManifestVersion1_1, artifactType, oras.PackManifestOptions{
		Subject:             &s,
		ManifestAnnotations: map[string]string{"name": name},
	})
	if err != nil {
		t.Fatalf("pack referrer %s: %v", name, err)
	}
	return desc
}

func exists(t *testing.T, store *oci.Store, desc ocispec.Descriptor) bool {
	t.Helper()
	ok, err := store.Exists(context.Background(), desc)
	if err != nil {
		t.Fatalf("Exists(%s): %v", desc.Digest, err)
	}
	return ok
}

func TestAttachIsDatedByNewestReport(t *testing.T) {
	f := newPruneFixture(t)
	referrers, err := Referrers(context.Background(), f.store, f.manifest)
	if err != nil {
		t.Fatalf("Referrers: %v", err)
	}
	if len(referrers) != 3 {
		t.Fatalf("got %d report referrers, want 3 (and neither the signature nor the foreign referrer)", len(referrers))
	}
	for i, r := range referrers {
		if want := f.reports[2-i].Digest; r.Digest != want {
			t.Errorf("referrers[%d] = %s, want %s (newest first)", i, r.Digest, want)
		}
	}
	if got := referrers[0].Annotations[AnnotationScanPlugin]; got != "grype" {
		t.Errorf("scan plugin annotation = %q, want grype", got)
	}
	if got := referrers[0].Annotations[ocispec.AnnotationCreated]; got != "2026-03-01T00:00:00Z" {
		t.Errorf("created = %q, want the report's scan time", got)
	}
}

func TestPruneReferrersKeepsNewest(t *testing.T) {
	f := newPruneFixture(t)

	deleted, err := PruneReferrers(context.Background(), f.store, f.manifest, 1)
	if err != nil {
		t.Fatalf("PruneReferrers: %v", err)
	}

	var deletedDigests []string
	for _, d := range deleted {
		deletedDigests = append(deletedDigests, d.Digest.String())
	}
	for i := range 2 {
		for _, gone := range []ocispec.Descriptor{f.reports[i], f.reportSig[i]} {
			if exists(t, f.store, gone) {
				t.Errorf("stale %s still exists", gone.Digest)
			}
			if !slices.Contains(deletedDigests, gone.Digest.String()) {
				t.Errorf("deleted list %v is missing %s", deletedDigests, gone.Digest)
			}
		}
	}
	for _, kept := range []ocispec.Descriptor{f.reports[2], f.reportSig[2], f.pkgSig, f.foreign, f.manifest} {
		if !exists(t, f.store, kept) {
			t.Errorf("%s was deleted, want it kept", kept.Digest)
		}
	}
}

func TestPruneReferrersKeepZeroDeletesNothing(t *testing.T) {
	f := newPruneFixture(t)
	deleted, err := PruneReferrers(context.Background(), f.store, f.manifest, 0)
	if err != nil || len(deleted) != 0 {
		t.Fatalf("PruneReferrers(keep=0) = %v, %v; want nothing deleted", deleted, err)
	}
	for _, r := range f.reports {
		if !exists(t, f.store, r) {
			t.Errorf("%s was deleted", r.Digest)
		}
	}
}

// refusingStore is an oci.Store that refuses every delete, like a
// registry that doesn't allow manifest deletes (e.g. ghcr.io).
type refusingStore struct{ *oci.Store }

func (refusingStore) Delete(context.Context, ocispec.Descriptor) error {
	return errors.New("405 method not allowed")
}

func TestPruneReferrersReportsRefusedDeletes(t *testing.T) {
	f := newPruneFixture(t)
	deleted, err := PruneReferrers(context.Background(), refusingStore{f.store}, f.manifest, 1)
	if err == nil {
		t.Fatal("PruneReferrers() error = nil, want the refused deletes reported")
	}
	if len(deleted) != 0 {
		t.Errorf("deleted = %v, want nothing", deleted)
	}
	// A refused signature delete must leave its report alone too, so the
	// signature isn't orphaned.
	for _, r := range f.reports {
		if !exists(t, f.store, r) {
			t.Errorf("%s was deleted despite its signature's delete failing", r.Digest)
		}
	}
}
