package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/security"
)

// gateFlags are the --fail-on/--ignore/--skip-gate flags deciding whether
// a scanned package's vulnerabilities fail the command.
type gateFlags struct {
	failOn string
	ignore []string
	skip   bool
}

func (f *gateFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", "fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching \"bomify security policy\" rule")
	cmd.Flags().StringArrayVar(&f.ignore, "ignore", nil, "a vulnerability ID never to fail on (repeatable); requires --fail-on")
	cmd.Flags().BoolVar(&f.skip, "skip-gate", false, "never fail on vulnerabilities, even if a \"bomify security policy\" rule matching the package says to")
}

// gate resolves the Gate applying to the package ref, checked in this
// order:
//  1. --skip-gate: nothing fails (with a warning if a rule would have).
//  2. --fail-on (plus --ignore): used as-is; rules aren't consulted.
//  3. The most specific <data-dir>/conf/scan.json rule matching ref.
//  4. Nothing matched: nothing fails.
func (f *gateFlags) gate(ref string, logger *slog.Logger) (security.Gate, error) {
	if f.skip && (f.failOn != "" || len(f.ignore) > 0) {
		return security.Gate{}, errors.New("--skip-gate cannot be combined with --fail-on or --ignore")
	}
	if len(f.ignore) > 0 && f.failOn == "" {
		return security.Gate{}, errors.New("--ignore requires --fail-on")
	}

	if f.failOn != "" {
		sev, err := security.ParseSeverity(f.failOn)
		if err != nil {
			return security.Gate{}, fmt.Errorf("--fail-on: %w", err)
		}
		return security.Gate{FailOn: sev, Ignore: f.ignore}, nil
	}

	rules, err := security.ReadConfig(dataDir)
	if err != nil {
		return security.Gate{}, err
	}
	rule, ok := security.Resolve(rules, ref)
	if !ok {
		return security.Gate{}, nil
	}

	g, err := rule.Gate()
	if err != nil {
		return security.Gate{}, err
	}
	if f.skip {
		if g.FailOn != 0 {
			logger.Warn("skipping vulnerability gate required by scan policy", "reference", ref, "match", rule.Match, "failOn", rule.FailOn)
		}
		return security.Gate{}, nil
	}
	return g, nil
}

// checkGate evaluates reports against g, printing a table of whatever
// fails it to w before returning the resulting error.
func checkGate(w io.Writer, g security.Gate, reports []security.ComponentReport) error {
	err := g.Check(reports)
	var gateErr *security.GateError
	if errors.As(err, &gateErr) {
		if werr := security.WriteFindings(w, gateErr.Findings); werr != nil {
			return errors.Join(err, werr)
		}
	}
	return err
}
