package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
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
	// "bomify security scan", "skip-scan" on the lifecycle hooks.
	skipFlag string
}

func (f *gateFlags) register(cmd *cobra.Command) {
	f.registerFlags(cmd, "skip-gate", "never fail on vulnerabilities, even if a \"bomify security policy\" rule matching the package says to")
}

func (f *gateFlags) registerFlags(cmd *cobra.Command, skipFlag, skipUsage string) {
	f.skipFlag = skipFlag
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", "fail if any vulnerability is at or above this severity (info, low, medium, high, critical); overrides a matching \"bomify security policy\" rule's")
	cmd.Flags().StringArrayVar(&f.ignore, "ignore", nil, "a vulnerability ID not to fail on, for this command only (repeatable); requires --fail-on")
	cmd.Flags().StringArrayVar(&f.vex, "vex", nil, "an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's")
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
	rules, err := security.ReadConfig(dataDir)
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

// scanFlags are the flags that scan a package at a lifecycle hook —
// build, push/save, pull/load — and gate it: --scan <type>, the gate
// flags, and --skip-scan.
type scanFlags struct {
	scanner string
	gateFlags
}

func (f *scanFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.scanner, "scan", "", "scan the package's components with the bomify-plugin-<type> scanner first (e.g. grype); overrides a matching \"bomify security policy\" rule's scanner")
	f.registerFlags(cmd, "skip-scan", "don't scan or gate at all, even if a \"bomify security policy\" rule matching the package says to")
}

// validate rejects flag combinations that contradict each other.
func (f *scanFlags) validate() error {
	if f.skip && f.scanner != "" {
		return errors.New("--skip-scan cannot be combined with --scan")
	}
	return f.gateFlags.validate()
}

// scanPlan is what a lifecycle hook does for one package: scan it fresh
// with Scanner (if set), then gate the result (or, with no Scanner, the
// local reports it already has) on Gate.
type scanPlan struct {
	Scanner string
	Gate    security.Gate
}

// active reports whether p does anything at all.
func (p scanPlan) active() bool {
	return p.Scanner != "" || p.Gate.FailOn != 0
}

// plan resolves what hook (see security.Hooks) does for the package ref.
// A matching scan policy rule only counts if it lists hook in its On
// (see security.Rule.AppliesOn); flags always do, and win over it:
//  1. --skip-scan: nothing (with a warning if the rule would have
//     scanned).
//  2. --scan, else the rule's scanner: scan fresh with it.
//  3. The gate, from --fail-on, else the rule's threshold (see gateFor).
func (f *scanFlags) plan(ref, hook string, logger *slog.Logger) (scanPlan, error) {
	if err := f.validate(); err != nil {
		return scanPlan{}, err
	}
	rule, matched, err := matchingScanRule(ref)
	if err != nil {
		return scanPlan{}, err
	}
	applies := matched && rule.AppliesOn(hook)

	if f.skip {
		if applies {
			logger.Warn("skipping vulnerability scan required by scan policy", "reference", ref, "match", rule.Match, "scanner", rule.Scanner, "hook", hook)
		}
		return scanPlan{}, nil
	}

	g, err := f.gateFor(ref, rule, applies, logger)
	if err != nil {
		return scanPlan{}, err
	}
	p := scanPlan{Scanner: f.scanner, Gate: g}
	if p.Scanner == "" && applies {
		p.Scanner = rule.Scanner
	}
	return p, nil
}

// planForTags is plan for a build or save of several tags at once: the
// first tag whose plan does anything decides, or, with no tags, the
// flags alone.
func (f *scanFlags) planForTags(tags []string, hook string, logger *slog.Logger) (scanPlan, error) {
	if len(tags) == 0 {
		return f.plan("", hook, logger)
	}
	for _, tag := range tags {
		p, err := f.plan(tag, hook, logger)
		if err != nil || p.active() {
			return p, err
		}
	}
	return scanPlan{}, nil
}

// run carries out p against components: a fresh scan with p.Scanner if
// set — returning its reports, for the caller to keep (see
// security.WriteReport) — or, with no scanner, the reports already in
// the data directory. Either way it then applies p.Gate, printing what
// fails it to w (see checkGate).
func (p scanPlan) run(w io.Writer, components []cdx.Component, concurrency int, logger *slog.Logger) ([]security.ComponentReport, error) {
	if p.Scanner == "" {
		reports, missing, err := security.ReadReports(dataDir, components)
		if err != nil {
			return nil, err
		}
		if len(missing) > 0 {
			logger.Warn("gating on local vulnerability reports, but some components have none (never scanned, or unsupported by the scanner); pass --scan to scan them", "components", len(missing))
		}
		return nil, checkGate(w, logger, p.Gate, reports)
	}

	path, err := plugin.Find(plugin.Dir(dataDir), p.Scanner)
	if err != nil {
		return nil, err
	}
	reports, err := security.Scan(path, p.Scanner, components, concurrency, logger)
	if err != nil {
		return nil, err
	}
	return reports, checkGate(w, logger, p.Gate, reports)
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

// gateLocalPackage runs p against the locally recorded package whose
// SBOM hashes to sbomHash — as build, push, and save do, before anything
// leaves the machine — keeping any fresh reports even when the gate
// fails, so what failed it can be inspected with "bomify package
// vulnerabilities".
func gateLocalPackage(w io.Writer, p scanPlan, sbomHash string, concurrency int, logger *slog.Logger) error {
	bom, err := sbom.Load(build.ManifestPath(dataDir, sbomHash))
	if err != nil {
		return fmt.Errorf("load sbom: %w", err)
	}
	var components []cdx.Component
	if bom.Components != nil {
		components = *bom.Components
	}

	reports, gateErr := p.run(w, components, concurrency, logger)
	if err := writeReports(reports); err != nil {
		return errors.Join(gateErr, err)
	}
	return gateErr
}

// pullScanner is the transfer.Scanner pull and load run for each
// package, before anything of it is written: it scans the SBOM's
// components fresh and gates them, collecting the reports for the
// caller to write once the pull succeeds (see collected). A package no
// plan applies to passes straight through.
type pullScanner struct {
	flags       *scanFlags
	w           io.Writer
	concurrency int
	logger      *slog.Logger
	collected   []security.ComponentReport
}

func (s *pullScanner) scan(_ context.Context, ref string, sbomData []byte) error {
	p, err := s.flags.plan(ref, security.HookPull, s.logger)
	if err != nil || !p.active() {
		return err
	}
	// The reports a pulled package carries are its publisher's, not a
	// verdict to trust: gating a pull always means scanning it here.
	if p.Scanner == "" {
		return errors.New("gating a pull or load needs a fresh scan: pass --scan <type> as well as --fail-on")
	}

	bom, err := sbom.LoadBytes(sbomData)
	if err != nil {
		return fmt.Errorf("parse sbom: %w", err)
	}
	var components []cdx.Component
	if bom.Components != nil {
		components = *bom.Components
	}

	reports, err := p.run(s.w, components, s.concurrency, s.logger.With("reference", ref))
	if err != nil {
		return err
	}
	s.collected = append(s.collected, reports...)
	return nil
}
