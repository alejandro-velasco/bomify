package scan

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

func TestToVulnerabilityFullMetadata(t *testing.T) {
	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "GHSA-jfh8-c2jp-5v3q", Namespace: "github:language:java"},
			Fix: vulnerability.Fix{
				State:    vulnerability.FixStateFixed,
				Versions: []string{"2.15.0"},
			},
			RelatedVulnerabilities: []vulnerability.Reference{
				{ID: "CVE-2021-44228", Namespace: "nvd:cpe"},
			},
			Metadata: &vulnerability.Metadata{
				DataSource:  "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
				Severity:    "Critical",
				Description: "Remote code injection in Log4j",
				CWEs: []vulnerability.CWE{
					{CWE: "CWE-20"},
					{CWE: "cwe-400"}, // lowercase, must still parse
					{CWE: "CWE-20"},  // duplicate, must be deduplicated
				},
				Cvss: []vulnerability.Cvss{
					{
						Source:  "nvd@nist.gov",
						Version: "3.1",
						Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
						Metrics: vulnerability.CvssMetrics{BaseScore: 10.0},
					},
				},
			},
		},
	}

	got := toVulnerability(m)

	if got.BOMRef != "GHSA-jfh8-c2jp-5v3q" || got.ID != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("BOMRef/ID = %q/%q, want GHSA-jfh8-c2jp-5v3q for both", got.BOMRef, got.ID)
	}
	if got.Description != "Remote code injection in Log4j" {
		t.Errorf("Description = %q", got.Description)
	}
	if got.Source == nil || got.Source.Name != "github:language:java" || got.Source.URL != "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("Source = %+v", got.Source)
	}
	if got.Recommendation != "Upgrade to version(s) 2.15.0." {
		t.Errorf("Recommendation = %q", got.Recommendation)
	}
	if got.Affects != nil {
		t.Errorf("Affects = %+v, want nil (bomify sets this, not the plugin)", got.Affects)
	}

	if got.CWEs == nil || len(*got.CWEs) != 2 {
		t.Fatalf("CWEs = %+v, want exactly 2 deduplicated entries", got.CWEs)
	}
	wantCWEs := map[int]bool{20: true, 400: true}
	for _, c := range *got.CWEs {
		if !wantCWEs[c] {
			t.Errorf("unexpected CWE %d", c)
		}
	}

	if got.References == nil || len(*got.References) != 1 {
		t.Fatalf("References = %+v, want 1 entry", got.References)
	}
	ref := (*got.References)[0]
	if ref.ID != "CVE-2021-44228" || ref.Source == nil || ref.Source.Name != "nvd:cpe" {
		t.Errorf("References[0] = %+v", ref)
	}

	if got.Ratings == nil || len(*got.Ratings) != 1 {
		t.Fatalf("Ratings = %+v, want 1 entry", got.Ratings)
	}
	rating := (*got.Ratings)[0]
	if rating.Score == nil || *rating.Score != 10.0 {
		t.Errorf("Ratings[0].Score = %v, want 10.0", rating.Score)
	}
	if rating.Severity != cdx.SeverityCritical {
		t.Errorf("Ratings[0].Severity = %q, want critical", rating.Severity)
	}
	if rating.Method != cdx.ScoringMethodCVSSv31 {
		t.Errorf("Ratings[0].Method = %q, want CVSSv31", rating.Method)
	}
	if rating.Source == nil || rating.Source.Name != "nvd@nist.gov" {
		t.Errorf("Ratings[0].Source = %+v", rating.Source)
	}
}

func TestToVulnerabilityNilMetadata(t *testing.T) {
	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-0001"},
		},
	}

	got := toVulnerability(m)

	if got.ID != "CVE-2024-0001" || got.BOMRef != "CVE-2024-0001" {
		t.Errorf("ID/BOMRef = %q/%q", got.ID, got.BOMRef)
	}
	if got.Description != "" || got.Source != nil || got.Ratings != nil || got.CWEs != nil || got.References != nil {
		t.Errorf("expected every metadata-derived field to be zero, got %+v", got)
	}
}

func TestToVulnerabilityNoCVSSFallsBackToSeverityOnlyRating(t *testing.T) {
	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "ALPINE-1"},
			Metadata:  &vulnerability.Metadata{Severity: "High"},
		},
	}

	got := toVulnerability(m)

	if got.Ratings == nil || len(*got.Ratings) != 1 {
		t.Fatalf("Ratings = %+v, want a single severity-only rating", got.Ratings)
	}
	rating := (*got.Ratings)[0]
	if rating.Severity != cdx.SeverityHigh {
		t.Errorf("Severity = %q, want high", rating.Severity)
	}
	if rating.Score != nil {
		t.Errorf("Score = %v, want nil (no CVSS data)", rating.Score)
	}
}

func TestToVulnerabilityUnknownSeverityAndNoCVSSOmitsRatings(t *testing.T) {
	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "ALPINE-2"},
			Metadata:  &vulnerability.Metadata{},
		},
	}

	got := toVulnerability(m)

	if got.Ratings != nil {
		t.Errorf("Ratings = %+v, want nil", got.Ratings)
	}
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		raw  string
		want cdx.Severity
	}{
		{"Critical", cdx.SeverityCritical},
		{"critical", cdx.SeverityCritical},
		{"HIGH", cdx.SeverityHigh},
		{"Medium", cdx.SeverityMedium},
		{"Low", cdx.SeverityLow},
		{"Negligible", cdx.SeverityInfo},
		{"", cdx.SeverityUnknown},
		{"garbage", cdx.SeverityUnknown},
	}
	for _, tt := range tests {
		if got := severity(tt.raw); got != tt.want {
			t.Errorf("severity(%q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestScoringMethodMapping(t *testing.T) {
	tests := []struct {
		version string
		want    cdx.ScoringMethod
	}{
		{"2.0", cdx.ScoringMethodCVSSv2},
		{"3.0", cdx.ScoringMethodCVSSv3},
		{"3.1", cdx.ScoringMethodCVSSv31},
		{"4.0", cdx.ScoringMethodCVSSv4},
		{"", cdx.ScoringMethodOther},
		{"9.9", cdx.ScoringMethodOther},
	}
	for _, tt := range tests {
		if got := scoringMethod(tt.version); got != tt.want {
			t.Errorf("scoringMethod(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestRecommendation(t *testing.T) {
	tests := []struct {
		name string
		fix  vulnerability.Fix
		want string
	}{
		{"fixed with version", vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: []string{"1.2.3"}}, "Upgrade to version(s) 1.2.3."},
		{"fixed with multiple versions", vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: []string{"1.2.3", "2.0.0"}}, "Upgrade to version(s) 1.2.3 | 2.0.0."},
		{"fixed, no version", vulnerability.Fix{State: vulnerability.FixStateFixed}, "Fixed; no specific version reported."},
		{"wont fix", vulnerability.Fix{State: vulnerability.FixStateWontFix}, "The vendor has stated this will not be fixed."},
		{"not fixed", vulnerability.Fix{State: vulnerability.FixStateNotFixed}, ""},
		{"unknown", vulnerability.Fix{State: vulnerability.FixStateUnknown}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := recommendation(tt.fix); got != tt.want {
				t.Errorf("recommendation() = %q, want %q", got, tt.want)
			}
		})
	}
}
