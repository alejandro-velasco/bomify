package security

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/table"
)

// Severity is a vulnerability severity bomify can gate on, ordered from
// least to most severe.
type Severity int

const (
	// SeverityNone is no severity at all, the zero value. As a
	// vulnerability's severity (rated only "none" or "unknown", or not
	// rated), it never reaches a threshold; as a Gate's FailOn, nothing
	// fails.
	SeverityNone Severity = iota
	SeverityInfo
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

// String returns s's CycloneDX name, or "none" for SeverityNone.
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
	return SeverityNone, fmt.Errorf("unknown severity %q (want one of info, low, medium, high, critical)", s)
}

// ConditionUnscanned is the --fail-on condition that fails a package any
// of whose components the scan skipped (see Gate.FailOnUnscanned).
const ConditionUnscanned = "unscanned"

// ParseFailOn parses --fail-on's conditions, case-insensitively, into
// the Gate they describe: at most one severity (see ParseSeverity), the
// threshold, and ConditionUnscanned. Ignore and VEX are left unset.
func ParseFailOn(conditions []string) (Gate, error) {
	var g Gate
	for _, condition := range conditions {
		if strings.EqualFold(condition, ConditionUnscanned) {
			g.FailOnUnscanned = true
			continue
		}
		sev, err := ParseSeverity(condition)
		if err != nil {
			return Gate{}, fmt.Errorf("unknown condition %q (want a severity: info, low, medium, high, critical; and/or %s)", condition, ConditionUnscanned)
		}
		if g.FailOn != SeverityNone {
			return Gate{}, fmt.Errorf("more than one severity (%s and %s): give the lowest that should fail", g.FailOn, sev)
		}
		g.FailOn = sev
	}
	return g, nil
}

// severityOf maps a CycloneDX rating severity onto Severity; "none",
// "unknown", and anything unrecognized map to SeverityNone.
func severityOf(s cdx.Severity) Severity {
	sev, _ := ParseSeverity(string(s))
	return sev
}

// Gate is a vulnerability threshold: a package fails it when any of its
// reports names a vulnerability at FailOn or above that isn't in Ignore
// and that VEX doesn't exempt, or, with FailOnUnscanned, when the scan
// skipped any of its components. A FailOn of SeverityNone fails nothing
// on vulnerabilities.
type Gate struct {
	FailOn Severity
	// FailOnUnscanned fails a package any of whose components the scanner
	// didn't scan (see Skipped), so that a component nothing checked never
	// passes as clean.
	FailOnUnscanned bool
	// Ignore lists vulnerability IDs (e.g. "CVE-2024-1234") never to fail
	// on, however severe — a one-off, for a single command.
	Ignore []string
	// VEX, if set, exempts any vulnerability its statements show doesn't
	// affect the component it was found in, or was fixed there (see
	// VEX.exempts).
	VEX *VEX
}

// CanFail reports whether g can fail a package at all: on a
// vulnerability threshold, on unscanned components, or both.
func (g Gate) CanFail() bool {
	return g.FailOn != SeverityNone || g.FailOnUnscanned
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
	if g.FailOn == SeverityNone {
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
	highest := SeverityNone
	if vuln.Ratings == nil {
		return highest
	}
	for _, rating := range *vuln.Ratings {
		highest = max(highest, severityOf(rating.Severity))
	}
	return highest
}

// GateError is returned when a package fails a Gate, carrying what
// failed it: Findings, Unscanned, or both.
type GateError struct {
	FailOn   Severity
	Findings []Finding
	// Unscanned are the components the scan skipped, set only when the
	// Gate fails on them (FailOnUnscanned).
	Unscanned []Skipped
}

func (e *GateError) Error() string {
	var reasons []string
	if n := len(e.Findings); n > 0 {
		reasons = append(reasons, fmt.Sprintf("%d %s at or above %s", n, plural(n, "vulnerability", "vulnerabilities"), e.FailOn))
	}
	if n := len(e.Unscanned); n > 0 {
		reasons = append(reasons, fmt.Sprintf("%d %s not scanned", n, plural(n, "component", "components")))
	}
	return strings.Join(reasons, "; ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Err returns a *GateError if anything failed g, the gate e came from —
// any finding, or, with g.FailOnUnscanned, any component in skipped, the
// ones the scan skipped (see Scan) — or nil.
func (e Evaluation) Err(g Gate, skipped []Skipped) error {
	err := &GateError{FailOn: g.FailOn, Findings: e.Findings}
	if g.FailOnUnscanned {
		err.Unscanned = skipped
	}
	if len(err.Findings) == 0 && len(err.Unscanned) == 0 {
		return nil
	}
	return err
}

// WriteFindings prints findings to w as a table.
func WriteFindings(w io.Writer, findings []Finding) error {
	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, []string{f.Severity.String(), f.ID, f.Purl})
	}
	return table.Write(w, []string{"SEVERITY", "ID", "COMPONENT"}, rows)
}

// WriteSkipped writes skipped, components a scan didn't scan, to w as a
// table: each one's purl (or name@version, without one) and why.
func WriteSkipped(w io.Writer, skipped []Skipped) error {
	rows := make([][]string, 0, len(skipped))
	for _, s := range skipped {
		label := s.Component.PackageURL
		if label == "" {
			label = s.Component.Name + "@" + s.Component.Version
		}
		rows = append(rows, []string{label, s.Reason})
	}
	return table.Write(w, []string{"COMPONENT", "REASON"}, rows)
}
