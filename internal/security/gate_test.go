package security

import (
	"errors"
	"reflect"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func vuln(id string, severities ...cdx.Severity) cdx.Vulnerability {
	var ratings []cdx.VulnerabilityRating
	for _, s := range severities {
		ratings = append(ratings, cdx.VulnerabilityRating{Severity: s, Method: cdx.ScoringMethodCVSSv31})
	}
	return cdx.Vulnerability{ID: id, Ratings: &ratings}
}

func reportFor(purl string, vulns ...cdx.Vulnerability) ComponentReport {
	return ComponentReport{
		Component: cdx.Component{PackageURL: purl},
		Report:    &cdx.BOM{Vulnerabilities: &vulns},
	}
}

func TestParseSeverity(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want Severity
	}{
		{"info", SeverityInfo}, {"LOW", SeverityLow}, {"Medium", SeverityMedium},
		{"high", SeverityHigh}, {"critical", SeverityCritical},
	} {
		got, err := ParseSeverity(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
		}
	}
	for _, bad := range []string{"", "none", "unknown", "severe"} {
		if _, err := ParseSeverity(bad); err == nil {
			t.Errorf("ParseSeverity(%q) error = nil, want one", bad)
		}
	}
}

func TestGateEvaluate(t *testing.T) {
	epss := 0.97
	kev := 1.0
	withScores := vuln("CVE-SCORES", cdx.SeverityMedium)
	*withScores.Ratings = append(*withScores.Ratings,
		cdx.VulnerabilityRating{Method: "EPSS", Score: &epss},
		cdx.VulnerabilityRating{Method: cdx.ScoringMethodOther, Score: &kev},
	)

	reports := []ComponentReport{
		reportFor("pkg:npm/a@1",
			vuln("CVE-LOW", cdx.SeverityLow),
			vuln("CVE-MIXED", cdx.SeverityMedium, cdx.SeverityCritical), // highest rating wins
			vuln("CVE-UNRATED"),
			vuln("CVE-UNKNOWN", cdx.SeverityUnknown),
			withScores, // EPSS/KEV scores carry no severity and don't raise it
		),
		reportFor("pkg:npm/b@1",
			vuln("CVE-HIGH", cdx.SeverityHigh),
			vuln("CVE-IGNORED", cdx.SeverityCritical),
			vuln("CVE-HIGH", cdx.SeverityHigh), // listed twice: reported once
		),
	}

	g := Gate{FailOn: SeverityHigh, Ignore: []string{"CVE-IGNORED"}}
	got := g.Evaluate(reports).Findings
	want := []Finding{
		{ID: "CVE-MIXED", Severity: SeverityCritical, Purl: "pkg:npm/a@1"},
		{ID: "CVE-HIGH", Severity: SeverityHigh, Purl: "pkg:npm/b@1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Evaluate() = %+v, want %+v", got, want)
	}

	if got := (Gate{FailOn: SeverityMedium}).Evaluate(reports[:1]).Findings; len(got) != 2 {
		t.Errorf("Evaluate(medium) = %+v, want CVE-MIXED and CVE-SCORES", got)
	}
	if got := (Gate{}).Evaluate(reports).Findings; got != nil {
		t.Errorf("zero Gate Evaluate() = %+v, want nothing", got)
	}
}

func TestEvaluationErr(t *testing.T) {
	reports := []ComponentReport{reportFor("pkg:npm/a@1", vuln("CVE-1", cdx.SeverityHigh))}

	err := Gate{FailOn: SeverityHigh}.Evaluate(reports).Err(SeverityHigh)
	var gateErr *GateError
	if !errors.As(err, &gateErr) || len(gateErr.Findings) != 1 {
		t.Fatalf("Err() = %v, want a GateError with one finding", err)
	}
	if want := "1 vulnerability at or above high"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}

	if err := (Gate{FailOn: SeverityCritical}).Evaluate(reports).Err(SeverityCritical); err != nil {
		t.Errorf("Err(critical) = %v, want nil", err)
	}
}
