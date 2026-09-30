package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
)

// gateFlags are the --fail-on/--ignore/--vex flags, plus a skip flag,
// deciding whether a scanned package's vulnerabilities fail the command.
type gateFlags struct {
	failOn string
	ignore []string
	vex    []string
	skip   bool
	// skipFlag names the skip flag, for messages: "skip-gate" on
	// "bomify security scan", where only the gate can be skipped — the
	// scan is the command itself — and "skip-scan" on pull and load,
	// where it skips both.
	skipFlag string
}

// register adds the gate flags to "bomify security scan". Only this
// explicit scan takes the one-off exemptions --ignore and --vex; pull
// and load rely on a rule's stored VEX instead.
func (f *gateFlags) register(cmd *cobra.Command) {
	f.registerThreshold(cmd, "skip-gate", "never fail on vulnerabilities, even if a \"bomify security policy\" rule matching the package says to")
	cmd.Flags().StringArrayVar(&f.ignore, "ignore", nil, "a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on")
	cmd.Flags().StringArrayVar(&f.vex, "vex", nil, "a VEX document (OpenVEX, CSAF, or CycloneDX) exempting what it marks not affected or fixed (repeatable); applied with a matching rule's")
}

// registerThreshold adds --fail-on and the command's skip flag, named
// skipFlag.
func (f *gateFlags) registerThreshold(cmd *cobra.Command, skipFlag, skipUsage string) {
	f.skipFlag = skipFlag
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", "fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching \"bomify security policy\" rule's")
	cmd.Flags().BoolVar(&f.skip, skipFlag, false, skipUsage)
}

// validate rejects flag combinations that contradict each other or do
// nothing.
func (f *gateFlags) validate() error {
	// Any of these shape the gate, which the skip flag would silently
	// throw away.
	configuresGate := f.failOn != "" || len(f.ignore) > 0 || len(f.vex) > 0

	if f.skip && configuresGate {
		return fmt.Errorf("--%s cannot be combined with --fail-on, --ignore, or --vex", f.skipFlag)
	}
	if len(f.ignore) > 0 && f.failOn == "" {
		return errors.New("--ignore requires --fail-on")
	}
	return nil
}

// gate resolves the Gate "bomify security scan" applies to the package
// ref: the most specific <data-dir>/conf/scan.json rule matching ref
// applies whatever hooks it lists, since an explicit scan is always its
// business (see gateFor).
func (f *gateFlags) gate(ref string, logger *slog.Logger) (security.Gate, error) {
	if err := f.validate(); err != nil {
		return security.Gate{}, err
	}
	rule, matched, err := matchingScanRule(ref)
	if err != nil {
		return security.Gate{}, err
	}
	return f.gateFor(ref, rule, matched, logger)
}

// matchingScanRule returns the most specific scan policy rule matching
// ref, if any.
func matchingScanRule(ref string) (security.Rule, bool, error) {
	rules, err := security.Read(dataDir)
	if err != nil {
		return security.Rule{}, false, err
	}
	rule, matched := security.Resolve(rules, ref)
	return rule, matched, nil
}

// gateFor resolves the Gate applying to the package ref, given the scan
// policy rule that applies to it (matched false if none does).
//
// Its threshold is decided in this order:
//  1. The skip flag: nothing fails (with a warning if the rule would
//     have).
//  2. --fail-on (plus --ignore): used as-is.
//  3. The rule's.
//  4. No rule: nothing fails.
//
// VEX documents are evidence rather than policy, so they add up instead:
// the rule's, then --vex's (so a --vex statement wins over a rule's where
// they disagree), whichever decided the threshold.
func (f *gateFlags) gateFor(ref string, rule security.Rule, matched bool, logger *slog.Logger) (security.Gate, error) {
	if !matched {
		rule = security.Rule{}
	}

	var g security.Gate
	var err error
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

// scanFlags are the flags that scan and gate a package as pull or load
// restores it: --scan <type>, --fail-on, and --skip-scan.
type scanFlags struct {
	scanner string
	gateFlags
}

func (f *scanFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.scanner, "scan", "", "scan the package with this scanner (e.g. grype) before anything is written, refusing it if --fail-on is met; overrides a matching \"bomify security policy\" rule's")
	f.registerThreshold(cmd, "skip-scan", "don't scan or gate at all, even if a \"bomify security policy\" rule matching the package says to")
}

// validate rejects flag combinations that contradict each other.
func (f *scanFlags) validate() error {
	if f.skip && f.scanner != "" {
		return errors.New("--skip-scan cannot be combined with --scan")
	}
	return f.gateFlags.validate()
}

// writeReports keeps reports in the data directory, as "bomify security
// scan" would.
func writeReports(reports []security.ComponentReport) error {
	for _, r := range reports {
		if _, err := security.WriteReport(dataDir, r.Component, r.Report); err != nil {
			return err
		}
	}
	return nil
}

// pullScanHook is the transfer.Hooks.Scan hook pull and load run for each
// package, before anything of it is written: it scans the SBOM's
// components fresh and gates them, collecting the reports for the
// caller to write once the pull succeeds (see collected).
type pullScanHook struct {
	flags       *scanFlags
	w           io.Writer
	concurrency int
	logger      *slog.Logger
	collected   []security.ComponentReport
}

// scan decides, for the package ref, whether to scan it and what gates
// it — a matching scan policy rule counts only if its On lists "pull",
// and flags win over it:
//  1. --skip-scan: nothing (with a warning if the rule would have
//     scanned).
//  2. --scan, else the rule's scanner.
//  3. The gate, from --fail-on, else the rule's threshold (see gateFor).
//
// It then scans fresh and gates. A scan here is only ever a gate, so a
// scanner with no threshold, or a threshold with no scanner, is an error
// rather than a scan that can't refuse anything or a gate on the
// publisher's own reports.
func (s *pullScanHook) scan(_ context.Context, ref string, sbomData []byte) error {
	f := s.flags
	if err := f.validate(); err != nil {
		return err
	}
	rule, matched, err := matchingScanRule(ref)
	if err != nil {
		return err
	}
	applies := matched && rule.AppliesOn(security.HookPull)

	if f.skip {
		if applies {
			s.logger.Warn("skipping vulnerability scan required by scan policy", "reference", ref, "match", rule.Match, "scanner", rule.Scanner)
		}
		return nil
	}

	scanner := f.scanner
	if scanner == "" && applies {
		scanner = rule.Scanner
	}
	gate, err := f.gateFor(ref, rule, applies, s.logger)
	if err != nil {
		return err
	}
	switch {
	case scanner == "" && gate.FailOn == 0:
		return nil
	case scanner == "":
		return errors.New("--fail-on needs --scan <type>: a pull always scans fresh, never trusting the reports a package carries")
	case gate.FailOn == 0:
		return errors.New("--scan needs --fail-on (or a matching rule's threshold) to refuse anything; to just scan, run \"bomify security scan\" after pulling")
	}

	bom, err := sbom.LoadBytes(sbomData)
	if err != nil {
		return fmt.Errorf("parse sbom: %w", err)
	}
	components := sbom.Components(bom.Components)

	path, err := plugin.Find(layout.Plugins(dataDir), scanner)
	if err != nil {
		return err
	}
	log := s.logger.With("reference", ref)
	reports, err := security.Scan(path, scanner, components, s.concurrency, log)
	if err != nil {
		return err
	}
	if err := checkGate(s.w, log, gate, reports); err != nil {
		return err
	}
	s.collected = append(s.collected, reports...)
	return nil
}
