package scan

import (
	"fmt"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

// toVulnerability builds the CycloneDX vulnerability describing m,
// entirely from fields grype's matcher already populated — no
// deprecated vulnerability.MetadataProvider.VulnerabilityMetadata call:
// m.Vulnerability.Metadata is populated directly by FindMatches (see
// grype/vulnerability/provider.go's own deprecation note on
// MetadataProvider: "vulnerability.Vulnerability objects now have
// metadata included").
//
// BOMRef is set to the vulnerability's own ID, per
// plugins/SECURITY-CONTRACT.md's recommended convention — this is what
// lets bomify recognize the same vulnerability reported by two
// different components and merge them, rather than duplicating it.
// Affects is deliberately left unset: bomify fills that in itself.
func toVulnerability(m match.Match) cdx.Vulnerability {
	v := cdx.Vulnerability{
		BOMRef: m.Vulnerability.ID,
		ID:     m.Vulnerability.ID,
	}

	if rec := recommendation(m.Vulnerability.Fix); rec != "" {
		v.Recommendation = rec
	}

	meta := m.Vulnerability.Metadata
	if meta == nil {
		return v
	}

	v.Description = meta.Description
	if meta.DataSource != "" || m.Vulnerability.Namespace != "" {
		v.Source = &cdx.Source{Name: m.Vulnerability.Namespace, URL: meta.DataSource}
	}
	v.Ratings = ratings(meta)
	v.CWEs = cwes(meta.CWEs)
	v.References = references(m.Vulnerability.RelatedVulnerabilities)

	return v
}

// ratings builds one CycloneDX rating per CVSS score grype's metadata
// reports, falling back to a single rating carrying just the overall
// severity when there's no CVSS data at all (grype still assigns a
// severity — e.g. from a distro's own advisory — even for sources that
// don't publish CVSS).
func ratings(meta *vulnerability.Metadata) *[]cdx.VulnerabilityRating {
	var out []cdx.VulnerabilityRating

	sev := severity(meta.Severity)
	for _, c := range meta.Cvss {
		score := c.Metrics.BaseScore
		rating := cdx.VulnerabilityRating{
			Score:    &score,
			Severity: sev,
			Method:   scoringMethod(c.Version),
			Vector:   c.Vector,
		}
		if c.Source != "" {
			rating.Source = &cdx.Source{Name: c.Source}
		}
		out = append(out, rating)
	}

	if len(out) == 0 && sev != cdx.SeverityUnknown {
		out = append(out, cdx.VulnerabilityRating{Severity: sev})
	}

	if len(out) == 0 {
		return nil
	}
	return &out
}

// severity maps grype's own severity string through its own
// case-insensitive parser (vulnerability.ParseSeverity) rather than
// assuming a particular casing, then onto the closest CycloneDX
// Severity — grype's "negligible" has no direct CycloneDX equivalent,
// so it maps to the closest one down from "low": "info".
func severity(raw string) cdx.Severity {
	switch vulnerability.ParseSeverity(raw) {
	case vulnerability.CriticalSeverity:
		return cdx.SeverityCritical
	case vulnerability.HighSeverity:
		return cdx.SeverityHigh
	case vulnerability.MediumSeverity:
		return cdx.SeverityMedium
	case vulnerability.LowSeverity:
		return cdx.SeverityLow
	case vulnerability.NegligibleSeverity:
		return cdx.SeverityInfo
	default:
		return cdx.SeverityUnknown
	}
}

// scoringMethod maps a CVSS version string (e.g. "2.0", "3.1") to its
// CycloneDX scoring method constant.
func scoringMethod(version string) cdx.ScoringMethod {
	switch {
	case strings.HasPrefix(version, "2"):
		return cdx.ScoringMethodCVSSv2
	case strings.HasPrefix(version, "3.0"):
		return cdx.ScoringMethodCVSSv3
	case strings.HasPrefix(version, "3.1"):
		return cdx.ScoringMethodCVSSv31
	case strings.HasPrefix(version, "4"):
		return cdx.ScoringMethodCVSSv4
	default:
		return cdx.ScoringMethodOther
	}
}

// cwes converts grype's CWE records to the bare CWE numbers CycloneDX
// expects, deduplicated and dropping any that don't parse as the
// "CWE-<number>" form grype's DB uses.
func cwes(in []vulnerability.CWE) *[]int {
	if len(in) == 0 {
		return nil
	}

	seen := map[int]bool{}
	var out []int
	for _, c := range in {
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(c.CWE), "CWE-"))
		if err != nil || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}

	if len(out) == 0 {
		return nil
	}
	return &out
}

// references converts every related vulnerability record (e.g. the GHSA
// behind a CVE, or vice versa) into a CycloneDX vulnerability reference.
func references(related []vulnerability.Reference) *[]cdx.VulnerabilityReference {
	if len(related) == 0 {
		return nil
	}

	out := make([]cdx.VulnerabilityReference, 0, len(related))
	for _, r := range related {
		ref := cdx.VulnerabilityReference{ID: r.ID}
		if r.Namespace != "" {
			ref.Source = &cdx.Source{Name: r.Namespace}
		}
		out = append(out, ref)
	}
	return &out
}

// recommendation renders fix information as free text — CycloneDX has
// no dedicated structured "fix version" field on Vulnerability, so this
// is the conventional place for it.
func recommendation(fix vulnerability.Fix) string {
	switch fix.State {
	case vulnerability.FixStateFixed:
		if len(fix.Versions) == 0 {
			return "Fixed; no specific version reported."
		}
		return fmt.Sprintf("Upgrade to version(s) %s.", strings.Join(fix.Versions, " | "))
	case vulnerability.FixStateWontFix:
		return "The vendor has stated this will not be fixed."
	default:
		return ""
	}
}
