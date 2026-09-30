package security

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Severity is a vulnerability severity bomify can gate on, ordered from
// least to most severe. The zero value is no severity at all: a
// vulnerability rated only "none" or "unknown", or not rated, never
// reaches any threshold.
type Severity int

const (
	SeverityInfo Severity = iota + 1
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// String returns s's CycloneDX name, or "none" for the zero value.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "none"
}

// ParseSeverity parses a --fail-on threshold: one of info, low, medium,
// high, or critical, case-insensitively.
func ParseSeverity(s string) (Severity, error) {
	for sev, name := range severityNames {
		if strings.EqualFold(s, name) {
			return sev, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want one of info, low, medium, high, critical)", s)
}

// severityOf maps a CycloneDX rating severity onto Severity; "none",
// "unknown", and anything unrecognized map to the zero value.
func severityOf(s cdx.Severity) Severity {
	sev, _ := ParseSeverity(string(s))
	return sev
}

// Gate is a vulnerability threshold: a package fails it when any of its
// reports names a vulnerability at FailOn or above that isn't in Ignore.
// A zero FailOn gates nothing.
type Gate struct {
	FailOn Severity
	// Ignore lists vulnerability IDs (e.g. "CVE-2024-1234") never to fail
	// on, however severe — accepted risks, false positives.
	Ignore []string
}

// Finding is one vulnerability that failed a Gate, in one component.
type Finding struct {
	ID       string
	Severity Severity
	// Purl is the scanned component the report belongs to — for an
	// unpacked component (e.g. an image), the image itself, not the
	// package inside it.
	Purl string
}

// ComponentReport is one component's vulnerability report.
type ComponentReport struct {
	Component cdx.Component
	Report    *cdx.BOM
}

// Evaluate returns every vulnerability in reports that fails g, most
// severe first (then by purl, then ID), at most once per component. A
// vulnerability's severity is the highest any of its ratings gives it;
// ratings that carry no severity (e.g. EPSS or CISA KEV scores) don't
// count either way.
func (g Gate) Evaluate(reports []ComponentReport) []Finding {
	if g.FailOn == 0 {
		return nil
	}

	var findings []Finding
	seen := map[[2]string]bool{}
	for _, r := range reports {
		if r.Report == nil || r.Report.Vulnerabilities == nil {
			continue
		}
		for _, vuln := range *r.Report.Vulnerabilities {
			if slices.Contains(g.Ignore, vuln.ID) {
				continue
			}
			sev := highestSeverity(vuln)
			if sev < g.FailOn {
				continue
			}
			key := [2]string{r.Component.PackageURL, vuln.ID}
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, Finding{ID: vuln.ID, Severity: sev, Purl: r.Component.PackageURL})
		}
	}

	slices.SortFunc(findings, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			strings.Compare(a.Purl, b.Purl),
			strings.Compare(a.ID, b.ID),
		)
	})
	return findings
}

func highestSeverity(vuln cdx.Vulnerability) Severity {
	var highest Severity
	if vuln.Ratings == nil {
		return highest
	}
	for _, rating := range *vuln.Ratings {
		highest = max(highest, severityOf(rating.Severity))
	}
	return highest
}

// GateError is returned when a package fails a Gate, carrying what
// failed it.
type GateError struct {
	FailOn   Severity
	Findings []Finding
}

func (e *GateError) Error() string {
	noun := "vulnerabilities"
	if len(e.Findings) == 1 {
		noun = "vulnerability"
	}
	return fmt.Sprintf("%d %s at or above %s", len(e.Findings), noun, e.FailOn)
}

// Check evaluates reports against g, returning a *GateError if anything
// fails it.
func (g Gate) Check(reports []ComponentReport) error {
	if findings := g.Evaluate(reports); len(findings) > 0 {
		return &GateError{FailOn: g.FailOn, Findings: findings}
	}
	return nil
}

// WriteFindings prints findings to w as a table.
func WriteFindings(w io.Writer, findings []Finding) error {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tID\tCOMPONENT")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", f.Severity, f.ID, f.Purl)
	}
	return tw.Flush()
}
