package scan

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/anchore/grype/grype/match"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
)

func TestImageReference(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want string
	}{
		{"plain tag", "pkg:oci/nginx@1.27", "nginx:1.27"},
		{"digest version", "pkg:oci/nginx@sha256:abcd1234", "nginx@sha256:abcd1234"},
		{"no version", "pkg:oci/nginx", "nginx"},
		{"namespace", "pkg:docker/library/nginx@1.27", "library/nginx:1.27"},
		{"tag qualifier preferred over version", "pkg:oci/nginx@1.27?tag=latest", "nginx:latest"},
		{
			"repository_url qualifier overrides name/namespace",
			"pkg:oci/nginx@1.27?repository_url=registry.example.com/mirror/nginx",
			"registry.example.com/mirror/nginx:1.27",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purl, err := packageurl.FromString(tt.purl)
			if err != nil {
				t.Fatalf("parse purl %q: %v", tt.purl, err)
			}

			if got := imageReference(purl); got != tt.want {
				t.Errorf("imageReference(%q) = %q, want %q", tt.purl, got, tt.want)
			}
		})
	}
}

func TestPackageRefPrefersPurl(t *testing.T) {
	p := grypePkg.Package{ID: "grype-id-1", PURL: "pkg:apk/openssl@1.1.1"}
	if got := packageRef(p); got != "pkg:apk/openssl@1.1.1" {
		t.Errorf("packageRef() = %q, want the purl", got)
	}
}

func TestPackageRefFallsBackToID(t *testing.T) {
	p := grypePkg.Package{ID: "grype-id-1"}
	if got := packageRef(p); got != "grype-id-1" {
		t.Errorf("packageRef() = %q, want the package ID since there's no purl", got)
	}
}

func TestToComponent(t *testing.T) {
	p := grypePkg.Package{ID: "grype-id-1", Name: "openssl", Version: "1.1.1", PURL: "pkg:apk/openssl@1.1.1"}

	got := toComponent(p)

	if got.BOMRef != "pkg:apk/openssl@1.1.1" {
		t.Errorf("BOMRef = %q, want the purl", got.BOMRef)
	}
	if got.Type != cdx.ComponentTypeLibrary {
		t.Errorf("Type = %q, want library", got.Type)
	}
	if got.Name != "openssl" || got.Version != "1.1.1" {
		t.Errorf("Name/Version = %q/%q", got.Name, got.Version)
	}
	if got.PackageURL != "pkg:apk/openssl@1.1.1" {
		t.Errorf("PackageURL = %q", got.PackageURL)
	}
	if got.Evidence != nil {
		t.Errorf("Evidence = %+v, want nil since the package has no locations", got.Evidence)
	}
}

func TestToComponentRecordsEvidenceOccurrencesFromLocations(t *testing.T) {
	locations := file.NewLocationSet(
		file.NewLocation("/lib/apk/db/installed"),
		file.NewLocation("/usr/lib/apk/db/installed"),
	)
	p := grypePkg.Package{ID: "grype-id-1", Name: "openssl", Version: "1.1.1", PURL: "pkg:apk/openssl@1.1.1", Locations: locations}

	got := toComponent(p)

	if got.Evidence == nil || got.Evidence.Occurrences == nil {
		t.Fatalf("Evidence.Occurrences = %+v, want one entry per location", got.Evidence)
	}
	occurrences := *got.Evidence.Occurrences
	if len(occurrences) != 2 {
		t.Fatalf("got %d occurrences, want 2: %+v", len(occurrences), occurrences)
	}
	paths := map[string]bool{}
	for _, occ := range occurrences {
		paths[occ.Location] = true
	}
	if !paths["/lib/apk/db/installed"] || !paths["/usr/lib/apk/db/installed"] {
		t.Errorf("occurrences = %+v, want both installed-db paths", occurrences)
	}
}

func TestAppendAffectedRefDedups(t *testing.T) {
	affects := appendAffectedRef(nil, "a")
	if affects == nil || len(*affects) != 1 || (*affects)[0].Ref != "a" {
		t.Fatalf("appendAffectedRef(nil, %q) = %+v", "a", affects)
	}

	affects = appendAffectedRef(affects, "a")
	if len(*affects) != 1 {
		t.Fatalf("appendAffectedRef with a duplicate ref grew the list: %+v", *affects)
	}

	affects = appendAffectedRef(affects, "b")
	if len(*affects) != 2 || (*affects)[1].Ref != "b" {
		t.Fatalf("appendAffectedRef(_, %q) = %+v", "b", *affects)
	}
}

// TestBuildImageResultAttributesAffectsToPackagesNotTheImage exercises the
// core nested-component behavior: buildImageResult must report every
// cataloged package as a component, and must point each vulnerability's
// Affects at the specific package(s) grype matched it against — folding
// the same vulnerability matched against more than one package into a
// single entry with multiple Affects, rather than duplicating it — never
// at anything else (there's no "image" component in this function's own
// inputs at all, only packages).
func TestBuildImageResultAttributesAffectsToPackagesNotTheImage(t *testing.T) {
	pkgA := grypePkg.Package{ID: "id-a", Name: "a", Version: "1.0", PURL: "pkg:apk/a@1.0"}
	pkgB := grypePkg.Package{ID: "id-b", Name: "b", Version: "1.0", PURL: "pkg:apk/b@1.0"}

	sharedOnA := match.Match{Package: pkgA, Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-SHARED"}}}
	sharedOnB := match.Match{Package: pkgB, Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-SHARED"}}}
	aOnly := match.Match{Package: pkgA, Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-A-ONLY"}}}

	matches := match.NewMatches(sharedOnA, sharedOnB, aOnly)

	result := buildImageResult([]grypePkg.Package{pkgA, pkgB}, &matches)

	if len(result.Components) != 2 {
		t.Fatalf("Components = %+v, want 2 (one per cataloged package)", result.Components)
	}
	componentRefs := map[string]bool{}
	for _, c := range result.Components {
		componentRefs[c.BOMRef] = true
	}
	if !componentRefs["pkg:apk/a@1.0"] || !componentRefs["pkg:apk/b@1.0"] {
		t.Errorf("Components = %+v, want entries for both pkg:apk/a@1.0 and pkg:apk/b@1.0", result.Components)
	}

	if len(result.Vulnerabilities) != 2 {
		t.Fatalf("Vulnerabilities = %+v, want 2 distinct entries (CVE-SHARED merged, CVE-A-ONLY separate)", result.Vulnerabilities)
	}

	byID := map[string]cdx.Vulnerability{}
	for _, v := range result.Vulnerabilities {
		byID[v.ID] = v
	}

	shared, ok := byID["CVE-SHARED"]
	if !ok {
		t.Fatal("CVE-SHARED missing from result")
	}
	if shared.Affects == nil || len(*shared.Affects) != 2 {
		t.Fatalf("CVE-SHARED.Affects = %+v, want 2 entries (both packages)", shared.Affects)
	}
	sharedRefs := map[string]bool{}
	for _, a := range *shared.Affects {
		sharedRefs[a.Ref] = true
	}
	if !sharedRefs["pkg:apk/a@1.0"] || !sharedRefs["pkg:apk/b@1.0"] {
		t.Errorf("CVE-SHARED.Affects = %+v, want refs for both packages, never the image", *shared.Affects)
	}

	aOnlyVuln, ok := byID["CVE-A-ONLY"]
	if !ok {
		t.Fatal("CVE-A-ONLY missing from result")
	}
	if aOnlyVuln.Affects == nil || len(*aOnlyVuln.Affects) != 1 || (*aOnlyVuln.Affects)[0].Ref != "pkg:apk/a@1.0" {
		t.Errorf("CVE-A-ONLY.Affects = %+v, want a single entry for pkg:apk/a@1.0", aOnlyVuln.Affects)
	}
}
