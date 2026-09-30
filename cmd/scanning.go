package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/security"
)

// gateFlags are the --fail-on/--ignore/--vex/--skip-gate flags deciding
// whether a scanned package's vulnerabilities fail the command.
type gateFlags struct {
	failOn string
	ignore []string
	vex    []string
	skip   bool
}

func (f *gateFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", "fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching \"bomify security policy\" rule's")
	cmd.Flags().StringArrayVar(&f.ignore, "ignore", nil, "a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on")
	cmd.Flags().StringArrayVar(&f.vex, "vex", nil, "an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's")
	cmd.Flags().BoolVar(&f.skip, "skip-gate", false, "never fail on vulnerabilities, even if a \"bomify security policy\" rule matching the package says to")
}

// validate rejects flag combinations that contradict each other or do
// nothing.
func (f *gateFlags) validate() error {
	// Any of these shape the gate, which --skip-gate would silently throw
	// away.
	configuresGate := f.failOn != "" || len(f.ignore) > 0 || len(f.vex) > 0

	if f.skip && configuresGate {
		return errors.New("--skip-gate cannot be combined with --fail-on, --ignore, or --vex")
	}
	if len(f.ignore) > 0 && f.failOn == "" {
		return errors.New("--ignore requires --fail-on")
	}
	return nil
}

// gate resolves the Gate applying to the package ref.
//
// Its threshold is decided in this order:
//  1. --skip-gate: nothing fails (with a warning if a rule would have).
//  2. --fail-on (plus --ignore): used as-is.
//  3. The most specific <data-dir>/conf/scan.json rule matching ref.
//  4. Nothing matched: nothing fails.
//
// VEX documents are evidence rather than policy, so they add up instead:
// the matching rule's, then --vex's (so a --vex statement wins over a
// rule's where they disagree), whichever decided the threshold.
func (f *gateFlags) gate(ref string, logger *slog.Logger) (security.Gate, error) {
	if err := f.validate(); err != nil {
		return security.Gate{}, err
	}

	rules, err := security.ReadConfig(dataDir)
	if err != nil {
		return security.Gate{}, err
	}
	rule, matched := security.Resolve(rules, ref)

	var g security.Gate
	switch {
	case f.failOn != "":
		g, err = f.flagGate()
	case matched:
		g, err = rule.Gate()
	}
	if err != nil {
		return security.Gate{}, err
	}

	if f.skip {
		if g.FailOn != 0 {
			logger.Warn("skipping vulnerability gate required by scan policy", "reference", ref, "match", rule.Match, "failOn", rule.FailOn)
		}
		return security.Gate{}, nil
	}

	// rule is the zero Rule, with no VEX, when nothing matched.
	ruleVEX, err := security.ResolveVEX(dataDir, rule.VEX)
	if err != nil {
		return security.Gate{}, fmt.Errorf("scan policy rule %q: %w", rule.Match, err)
	}
	if g.VEX, err = f.loadVEX(ruleVEX, g.FailOn, ref, logger); err != nil {
		return security.Gate{}, err
	}
	return g, nil
}

// flagGate builds the Gate --fail-on and --ignore describe, the
// command-line counterpart to security.Rule.Gate.
func (f *gateFlags) flagGate() (security.Gate, error) {
	sev, err := security.ParseSeverity(f.failOn)
	if err != nil {
		return security.Gate{}, fmt.Errorf("--fail-on: %w", err)
	}
	return security.Gate{FailOn: sev, Ignore: f.ignore}, nil
}

// loadVEX loads ruleVEX's documents (stored copies' paths), then --vex's — so a --vex statement
// wins over a rule's where they disagree — or returns nil if there are
// none. With no threshold (failOn 0) nothing can fail anyway, so it
// warns that the documents won't change anything.
func (f *gateFlags) loadVEX(ruleVEX []string, failOn security.Severity, ref string, logger *slog.Logger) (*security.VEX, error) {
	paths := append(slices.Clone(ruleVEX), f.vex...)
	if len(paths) == 0 {
		return nil, nil
	}
	if failOn == 0 {
		logger.Warn("VEX given, but no --fail-on or scan policy threshold applies, so nothing can fail", "reference", ref)
	}
	return security.LoadVEX(paths)
}

// checkGate evaluates reports against g, logging every vulnerability VEX
// exempted — so a suppression is never silent — and printing a table of
// whatever fails it to w before returning the resulting error.
func checkGate(w io.Writer, logger *slog.Logger, g security.Gate, reports []security.ComponentReport) error {
	e := g.Evaluate(reports)
	for _, s := range e.Suppressed {
		logger.Info("vulnerability exempted by VEX", "id", s.ID, "severity", s.Severity.String(), "component", s.Purl,
			"status", s.Statement.Status, "justification", s.Statement.Justification,
			"impact", s.Statement.ImpactStatement, "source", s.Statement.Source)
	}

	err := e.Err(g.FailOn)
	var gateErr *security.GateError
	if errors.As(err, &gateErr) {
		if werr := security.WriteFindings(w, gateErr.Findings); werr != nil {
			return errors.Join(err, werr)
		}
	}
	return err
}
