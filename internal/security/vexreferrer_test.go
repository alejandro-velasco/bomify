package security

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// vexDoc is an OpenVEX document giving CVE-1 in pkgA the given status.
func vexDoc(status string) string {
	extra := `"justification":"component_not_present"`
	if status == "affected" {
		extra = `"action_statement":"upgrade"`
	}
	return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"` + status + `","timestamp":"2026-01-01T00:00:00Z",
		"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"` + pkgA + `"}],"status":"` + status + `",` + extra + `}]}`
}

// publishVEX returns a store holding a package manifest with each of
// bodies attached as a VEX document, in order.
func publishVEX(t *testing.T, bodies ...string) (*oci.Store, ocispec.Descriptor) {
	t.Helper()
	ctx := context.Background()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	manifest, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, transfer.ArtifactType, oras.PackManifestOptions{})
	if err != nil {
		t.Fatalf("pack package manifest: %v", err)
	}
	for i, body := range bodies {
		doc := VEXDocument{Name: string(rune('a' + i)), Data: []byte(body)}
		if _, _, err := transfer.Attach(ctx, store, manifest, doc.Attachment(), nil); err != nil {
			t.Fatalf("attach VEX: %v", err)
		}
	}
	return store, manifest
}

func acceptAll(context.Context, oras.ReadOnlyTarget, string, ocispec.Descriptor) error { return nil }

func TestPublishedVEX(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, manifest := publishVEX(t, vexDoc("not_affected"))
	report := directReport(pkgA)

	// Verified: the publisher's statement exempts CVE-1, labeled with where
	// it came from.
	v := PublishedVEX(ctx, store, "app:1", manifest, acceptAll, logger)
	if e := gateWith(v).Evaluate([]ComponentReport{report}); len(e.Findings) != 0 {
		t.Errorf("verified: %+v, want CVE-1 exempted", e)
	}
	for _, s := range v.statements {
		if !strings.HasPrefix(s.Source, "published with app:1: sha256:") {
			t.Errorf("statement source = %q, want the reference and referrer digest", s.Source)
		}
	}

	// A pull that verifies nothing counts none.
	if v := PublishedVEX(ctx, store, "app:1", manifest, nil, logger); v != nil {
		t.Errorf("unverified pull: %+v, want no VEX", v)
	}

	// Each document needs its own verification: the package verifying
	// isn't enough.
	reject := func(context.Context, oras.ReadOnlyTarget, string, ocispec.Descriptor) error {
		return errors.New("unsigned")
	}
	if v := PublishedVEX(ctx, store, "app:1", manifest, reject, logger); v != nil {
		t.Errorf("unverified document: %+v, want it ignored", v)
	}
}

// TestPublishedVEXOrder covers precedence among publications: a
// document attached later wins over an earlier one where they disagree.
func TestPublishedVEXOrder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	report := directReport(pkgA)

	store, manifest := publishVEX(t, vexDoc("affected"), vexDoc("not_affected"))
	v := PublishedVEX(context.Background(), store, "app:1", manifest, acceptAll, logger)
	if e := gateWith(v).Evaluate([]ComponentReport{report}); len(e.Findings) != 0 {
		t.Errorf("affected then not_affected: %+v, want CVE-1 exempted", e)
	}

	store, manifest = publishVEX(t, vexDoc("not_affected"), vexDoc("affected"))
	v = PublishedVEX(context.Background(), store, "app:1", manifest, acceptAll, logger)
	if e := gateWith(v).Evaluate([]ComponentReport{report}); len(e.Findings) != 1 {
		t.Errorf("not_affected then affected: %+v, want CVE-1 to fail", e)
	}
}

// TestCombineVEX covers precedence: the second set's statements win
// where the two disagree, as local VEX wins over a publisher's.
func TestCombineVEX(t *testing.T) {
	notAffected := loadVEX(t, vexDoc("not_affected"))
	affected := loadVEX(t, vexDoc("affected"))
	report := directReport(pkgA)

	if e := gateWith(CombineVEX(affected, notAffected)).Evaluate([]ComponentReport{report}); len(e.Findings) != 0 {
		t.Errorf("affected then not_affected: %+v, want CVE-1 exempted", e)
	}
	if e := gateWith(CombineVEX(notAffected, affected)).Evaluate([]ComponentReport{report}); len(e.Findings) != 1 {
		t.Errorf("not_affected then affected: %+v, want CVE-1 to fail", e)
	}
	if CombineVEX(nil, affected) != affected || CombineVEX(affected, nil) != affected {
		t.Error("CombineVEX with a nil side should return the other")
	}
}

func TestReadVEX(t *testing.T) {
	baseDir := t.TempDir()
	path := writeVEX(t, "team.openvex.json", vexDoc("not_affected"))
	if _, err := AddVEX(baseDir, "team", path); err != nil {
		t.Fatalf("AddVEX: %v", err)
	}

	if doc, err := ReadVEX(baseDir, "team"); err != nil || doc.Name != "team" {
		t.Errorf("ReadVEX(stored name) = %q, %v; want the stored document", doc.Name, err)
	}
	if doc, err := ReadVEX(baseDir, path); err != nil || doc.Name != "team.openvex.json" {
		t.Errorf("ReadVEX(file) = %q, %v; want the file, named by its base name", doc.Name, err)
	}
	if _, err := ReadVEX(baseDir, "missing"); err == nil {
		t.Error("ReadVEX(neither a stored name nor a file): error = nil, want one")
	}
	if _, err := ReadVEX(baseDir, writeVEX(t, "junk.json", `{"hello":1}`)); err == nil {
		t.Error("ReadVEX(not VEX): error = nil, want one")
	}
}
