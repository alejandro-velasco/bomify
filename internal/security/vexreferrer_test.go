package security

import (
	"context"
	"strings"
	"testing"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

const (
	vexDocA = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"a","timestamp":"2026-01-01T00:00:00Z",
		"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"not_affected","justification":"component_not_present"}]}`
	vexDocB = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"b","timestamp":"2026-01-01T00:00:00Z",
		"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:npm/a@1"}],"status":"affected","action_statement":"upgrade"}]}`
)

func TestAttachVEX(t *testing.T) {
	ctx := context.Background()
	store, err := oci.New(t.TempDir())
	if err != nil {
		t.Fatalf("new oci store: %v", err)
	}
	manifest, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, transfer.ArtifactType, oras.PackManifestOptions{})
	if err != nil {
		t.Fatalf("pack package manifest: %v", err)
	}

	docs := []VEXDocument{{Name: "a.json", Data: []byte(vexDocA)}, {Name: "b.json", Data: []byte(vexDocB)}}
	attached, err := AttachVEX(ctx, store, manifest, docs)
	if err != nil || len(attached) != 2 {
		t.Fatalf("AttachVEX = %v, %v; want one referrer per document", attached, err)
	}

	// The same documents again attach nothing new.
	again, err := AttachVEX(ctx, store, manifest, docs[:1])
	if err != nil || len(again) != 0 {
		t.Fatalf("AttachVEX (again) = %v, %v; want nothing attached", again, err)
	}

	referrers, err := VEXReferrers(ctx, store, manifest)
	if err != nil || len(referrers) != 2 {
		t.Fatalf("VEXReferrers = %v, %v; want 2", referrers, err)
	}
	var fetched []VEXDocument
	for _, r := range referrers {
		doc, err := FetchVEX(ctx, store, r)
		if err != nil {
			t.Fatalf("FetchVEX: %v", err)
		}
		fetched = append(fetched, doc)
	}
	var got []string
	for _, doc := range fetched {
		got = append(got, string(doc.Data))
	}
	if !contains(got, vexDocA) || !contains(got, vexDocB) {
		t.Errorf("fetched documents = %v, want both", got)
	}

	// Loaded, each statement is labeled with where it came from.
	v, err := LoadVEXDocuments(fetched, "published with app: ")
	if err != nil {
		t.Fatalf("LoadVEXDocuments: %v", err)
	}
	for _, s := range v.statements {
		if !strings.HasPrefix(s.Source, "published with app: sha256:") {
			t.Errorf("statement source = %q, want the publisher label and referrer digest", s.Source)
		}
	}
}

// TestCombineVEX covers precedence: the second set's statements win
// where the two disagree, as local VEX wins over a publisher's.
func TestCombineVEX(t *testing.T) {
	notAffected := loadVEX(t, strings.Replace(vexDocA, `"pkg:npm/a@1"`, `"`+pkgA+`"`, 1))
	affected := loadVEX(t, strings.Replace(vexDocB, `"pkg:npm/a@1"`, `"`+pkgA+`"`, 1))
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

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
