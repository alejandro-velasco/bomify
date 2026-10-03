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

	err := Gate{FailOn: SeverityHigh}.Evaluate(reports).Err(Gate{FailOn: SeverityHigh}, nil)
	var gateErr *GateError
	if !errors.As(err, &gateErr) || len(gateErr.Findings) != 1 {
		t.Fatalf("Err() = %v, want a GateError with one finding", err)
	}
	if want := "1 vulnerability at or above high"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}

	if err := (Gate{FailOn: SeverityCritical}).Evaluate(reports).Err(Gate{FailOn: SeverityCritical}, nil); err != nil {
		t.Errorf("Err(critical) = %v, want nil", err)
	}
}

func TestErrUnscanned(t *testing.T) {
	skipped := []Skipped{{Component: cdx.Component{PackageURL: "pkg:npm/b@1.0"}, Reason: `unsupported type "npm"`}}
	reports := []ComponentReport{reportFor("pkg:generic/a@1.0", vuln("CVE-HIGH", cdx.SeverityHigh))}

	// Skipped components only fail a gate that asks for it.
	if err := (Gate{}).Evaluate(reports).Err(Gate{}, skipped); err != nil {
		t.Errorf("without FailOnUnscanned: %v, want nil", err)
	}

	g := Gate{FailOnUnscanned: true}
	err := g.Evaluate(reports).Err(g, skipped)
	var gateErr *GateError
	if !errors.As(err, &gateErr) || len(gateErr.Unscanned) != 1 || len(gateErr.Findings) != 0 {
		t.Fatalf("FailOnUnscanned: %v, want a GateError with one unscanned component", err)
	}
	if got, want := err.Error(), "1 component not scanned"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if err := g.Evaluate(reports).Err(g, nil); err != nil {
		t.Errorf("FailOnUnscanned with nothing skipped: %v, want nil", err)
	}

	g = Gate{FailOn: SeverityHigh, FailOnUnscanned: true}
	err = g.Evaluate(reports).Err(g, skipped)
	if got, want := err.Error(), "1 vulnerability at or above high; 1 component not scanned"; got != want {
		t.Errorf("both: Error() = %q, want %q", got, want)
	}
}

func TestRuleGateFailOnUnscanned(t *testing.T) {
	for _, r := range []Rule{{FailOnUnscanned: true}, {FailOn: "high", FailOnUnscanned: true}} {
		g, err := r.Gate()
		if err != nil || !g.FailOnUnscanned {
			t.Errorf("%+v.Gate() = %+v, %v; want FailOnUnscanned", r, g, err)
		}
	}
}

func TestCanFail(t *testing.T) {
	for _, tc := range []struct {
		gate Gate
		want bool
	}{
		{Gate{}, false},
		{Gate{FailOn: SeverityLow}, true},
		{Gate{FailOnUnscanned: true}, true},
		{Gate{FailOn: SeverityHigh, FailOnUnscanned: true}, true},
	} {
		if got := tc.gate.CanFail(); got != tc.want {
			t.Errorf("%+v.CanFail() = %v, want %v", tc.gate, got, tc.want)
		}
	}
	for _, tc := range []struct {
		rule Rule
		want bool
	}{
		{Rule{}, false},
		{Rule{FailOn: "low"}, true},
		{Rule{FailOnUnscanned: true}, true},
	} {
		if got := tc.rule.CanFail(); got != tc.want {
			t.Errorf("%+v.CanFail() = %v, want %v", tc.rule, got, tc.want)
		}
	}
}

func TestParseFailOn(t *testing.T) {
	for _, tc := range []struct {
		conditions []string
		want       Gate
		wantErr    bool
	}{
		{conditions: nil, want: Gate{}},
		{conditions: []string{"high"}, want: Gate{FailOn: SeverityHigh}},
		{conditions: []string{"unscanned"}, want: Gate{FailOnUnscanned: true}},
		{conditions: []string{"Unscanned", "HIGH"}, want: Gate{FailOn: SeverityHigh, FailOnUnscanned: true}},
		{conditions: []string{"high", "low"}, wantErr: true},
		{conditions: []string{"severe"}, wantErr: true},
		{conditions: []string{""}, wantErr: true},
	} {
		got, err := ParseFailOn(tc.conditions)
		if (err != nil) != tc.wantErr || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParseFailOn(%q) = %+v, %v; want %+v, error %v", tc.conditions, got, err, tc.want, tc.wantErr)
		}
	}
}
