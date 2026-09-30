package security

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/alejandro-velasco/bomify/internal/sbom"
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
// reports names a vulnerability at FailOn or above that isn't in Ignore
// and that VEX doesn't exempt. A zero FailOn gates nothing.
type Gate struct {
	FailOn Severity
	// Ignore lists vulnerability IDs (e.g. "CVE-2024-1234") never to fail
	// on, however severe — a one-off, for a single command.
	Ignore []string
	// VEX, if set, exempts any vulnerability its statements show doesn't
	// affect the component it was found in, or was fixed there (see
	// VEX.exempts).
	VEX *VEX
}

// Finding is one vulnerability at or above a Gate's threshold, in one
// component.
type Finding struct {
	ID       string
	Severity Severity
	// Purl is the scanned component the report belongs to — for an
	// unpacked component (e.g. an image), the image itself, not the
	// package inside it.
	Purl string
}

// Suppressed is a Finding a VEX statement exempted from failing a Gate,
// and the statement that did.
type Suppressed struct {
	Finding
	Statement SourcedStatement
}

// Evaluation is the outcome of evaluating reports against a Gate.
type Evaluation struct {
	// Findings failed the gate.
	Findings []Finding
	// Suppressed would have, but VEX exempted them.
	Suppressed []Suppressed
}

// ComponentReport is one component's vulnerability report.
type ComponentReport struct {
	Component cdx.Component
	Report    *cdx.BOM
}

// Evaluate returns every vulnerability in reports that fails g, and every
// one VEX exempted from failing it, each most severe first (then by
// purl, then ID), at most once per component. A vulnerability's severity
// is the highest any of its ratings gives it; ratings that carry no
// severity (e.g. EPSS or CISA KEV scores) don't count either way.
func (g Gate) Evaluate(reports []ComponentReport) Evaluation {
	var e Evaluation
	if g.FailOn == 0 {
		return e
	}

	seen := map[[2]string]bool{}
	for _, r := range reports {
		if r.Report == nil || r.Report.Vulnerabilities == nil {
			continue
		}
		// Built once per report, since every vulnerability in it resolves
		// its "affects" against the same components.
		purlByRef := purlsByBOMRef(sbom.Components(r.Report.Components))
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
			finding := Finding{ID: vuln.ID, Severity: sev, Purl: r.Component.PackageURL}
			if statement, ok := g.VEX.exempts(r.Component, purlByRef, vuln); ok {
				e.Suppressed = append(e.Suppressed, Suppressed{Finding: finding, Statement: statement})
				continue
			}
			e.Findings = append(e.Findings, finding)
		}
	}

	slices.SortFunc(e.Findings, compareFindings)
	slices.SortFunc(e.Suppressed, func(a, b Suppressed) int { return compareFindings(a.Finding, b.Finding) })
	return e
}

func compareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(b.Severity, a.Severity),
		strings.Compare(a.Purl, b.Purl),
		strings.Compare(a.ID, b.ID),
	)
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

// Err returns a *GateError if anything failed the gate e came from, or
// nil.
func (e Evaluation) Err(failOn Severity) error {
	if len(e.Findings) > 0 {
		return &GateError{FailOn: failOn, Findings: e.Findings}
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
