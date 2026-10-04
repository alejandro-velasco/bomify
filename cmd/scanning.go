package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/signature"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// gateFlags are the --fail-on/--ignore/--vex flags, plus a skip flag,
// deciding whether a scanned package fails the command.
type gateFlags struct {
	// failOn are --fail-on's conditions (see security.ParseFailOn).
	failOn []string
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
	cmd.Flags().StringSliceVar(&f.failOn, "fail-on", nil, failOnUsage+"; replaces a matching \"bomify security policy\" rule's")
	cmd.Flags().BoolVar(&f.skip, skipFlag, false, skipUsage)
}

// validate rejects flag combinations that contradict each other or do
// nothing.
func (f *gateFlags) validate() error {
	// Any of these shape the gate, which the skip flag would silently
	// throw away.
	configuresGate := len(f.failOn) > 0 || len(f.ignore) > 0 || len(f.vex) > 0

	if f.skip && configuresGate {
		return fmt.Errorf("--%s cannot be combined with --fail-on, --ignore, or --vex", f.skipFlag)
	}
	g, err := f.flagGate()
	if err != nil {
		return err
	}
	if len(f.ignore) > 0 && g.FailOn == security.SeverityNone {
		return errors.New("--ignore requires a severity in --fail-on")
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
//  2. --fail-on (plus --ignore): used as-is, replacing all of the rule's
//     conditions, unscanned included.
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
	case len(f.failOn) > 0:
		g, err = f.flagGate()
	case matched:
		g, err = rule.Gate()
	}
	if err != nil {
		return security.Gate{}, err
	}

	if f.skip {
		if g.CanFail() {
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

// failOnUsage describes --fail-on's conditions, for every command that
// takes it.
const failOnUsage = "fail on these comma-separated `conditions`: a severity (info, low, medium, high, critical) that any vulnerability at or above fails, and/or \"unscanned\", failing if any component no scanner scanned"

// flagGate builds the Gate --fail-on and --ignore describe, the
// command-line counterpart to security.Rule.Gate.
func (f *gateFlags) flagGate() (security.Gate, error) {
	g, err := security.ParseFailOn(f.failOn)
	if err != nil {
		return security.Gate{}, fmt.Errorf("--fail-on: %w", err)
	}
	g.Ignore = f.ignore
	return g, nil
}

// loadVEX loads ruleVEX's documents (stored copies' paths), then --vex's — so a --vex statement
// wins over a rule's where they disagree — or returns nil if there are
// none. With no threshold (SeverityNone) nothing can fail anyway, so it
// warns that the documents won't change anything.
func (f *gateFlags) loadVEX(ruleVEX []string, failOn security.Severity, ref string, logger *slog.Logger) (*security.VEX, error) {
	paths := slices.Concat(ruleVEX, f.vex)
	if len(paths) == 0 {
		return nil, nil
	}
	if failOn == security.SeverityNone {
		logger.Warn("VEX given, but no --fail-on or scan policy threshold applies, so nothing can fail", "reference", ref)
	}
	return security.LoadVEX(paths)
}

// checkGate prints a table of the components result's scan skipped to
// w, then evaluates its reports and skipped components against g, logging
// every vulnerability VEX exempted — so a suppression is never silent —
// and printing a table of whatever fails it to w before returning the
// resulting error.
func checkGate(w io.Writer, logger *slog.Logger, g security.Gate, result security.ScanResult) error {
	if len(result.Skipped) > 0 {
		fmt.Fprintf(w, "%d of %d components not scanned by %s:\n", len(result.Skipped), result.Components, strings.Join(result.Scanners, " or "))
		if err := security.WriteSkipped(w, result.Skipped); err != nil {
			return err
		}
	}

	e := g.Evaluate(result.Reports)
	for _, s := range e.Suppressed {
		logger.Info("vulnerability exempted by VEX", "id", s.ID, "severity", s.Severity.String(), "component", s.Purl,
			"status", s.Statement.Status, "justification", s.Statement.Justification,
			"impact", s.Statement.ImpactStatement, "source", s.Statement.Source)
	}

	err := e.Err(g, result.Skipped)
	var gateErr *security.GateError
	if errors.As(err, &gateErr) && len(gateErr.Findings) > 0 {
		if werr := security.WriteFindings(w, gateErr.Findings); werr != nil {
			return errors.Join(err, werr)
		}
	}
	return err
}

// scanFlags are the flags that scan and gate a package as pull or load
// restores it: --scan <scanners>, --fail-on, and --skip-scan.
type scanFlags struct {
	scanners []string
	gateFlags
}

func (f *scanFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&f.scanners, "scan", nil, "scan the package with these comma-separated `scanners` (e.g. grype) before it's tagged, refusing it if --fail-on is met; overrides a matching \"bomify security policy\" rule's")
	f.registerThreshold(cmd, "skip-scan", "don't scan or gate at all, even if a \"bomify security policy\" rule matching the package says to")
}

// validate rejects flag combinations that contradict each other.
func (f *scanFlags) validate() error {
	if f.skip && len(f.scanners) > 0 {
		return errors.New("--skip-scan cannot be combined with --scan")
	}
	return f.gateFlags.validate()
}

// findScanners checks scanners (see security.CheckScanners) and finds
// each one's plugin.
func findScanners(scanners []string) ([]security.ScanPlugin, error) {
	if err := security.CheckScanners(scanners); err != nil {
		return nil, err
	}
	plugins := make([]security.ScanPlugin, 0, len(scanners))
	for _, scanner := range scanners {
		path, err := plugin.Find(layout.Plugins(dataDir), scanner, pluginlib.SecurityContract)
		if err != nil {
			return nil, err
		}
		plugins = append(plugins, security.ScanPlugin{Name: scanner, Path: path})
	}
	return plugins, nil
}

// writeReports keeps reports in the data directory, as "bomify security
// scan" would.
func writeReports(reports []security.ComponentReport) error {
	for _, r := range reports {
		if _, err := security.WriteReport(dataDir, r); err != nil {
			return err
		}
	}
	return nil
}

// pullScanHook is the transfer.Hooks.Scan hook pull and load run for each
// package once its layers are written, before it's tagged: it scans the
// SBOM's components fresh and gates them, collecting the reports for the
// caller to write once the pull succeeds (see collected).
type pullScanHook struct {
	flags       *scanFlags
	w           io.Writer
	concurrency int
	logger      *slog.Logger
	collected   []security.ComponentReport
	// policy and verify are the pull's signature verification: VEX the
	// package's publisher attached counts only where they verify it (see
	// security.PublishedVEX).
	policy signature.Policy
	verify transfer.Verifier
}

// scan decides, for the package ref, whether to scan it and what gates
// it — a matching scan policy rule counts only if its On lists "pull",
// and flags win over it:
//  1. --skip-scan: nothing (with a warning if the rule would have
//     scanned).
//  2. --scan, else the rule's scanners.
//  3. The gate, from --fail-on, else the rule's threshold (see gateFor),
//     plus VEX the package's publisher attached, when this pull verifies
//     it (see security.PublishedVEX).
//
// It then scans fresh and gates. A scan here is only ever a gate, so a
// scanner with no threshold, or a threshold with no scanner, is an error
// rather than a scan that can't refuse anything or a gate on the
// publisher's own reports.
func (s *pullScanHook) scan(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor, sbomData []byte) error {
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
			s.logger.Warn("skipping vulnerability scan required by scan policy", "reference", ref, "match", rule.Match, "scanners", rule.Scanners)
		}
		return nil
	}

	// --scan wins over the rule's scanners, which only count if the rule
	// applies on pull.
	scanners := f.scanners
	if len(scanners) == 0 && applies {
		scanners = rule.Scanners
	}

	gate, err := f.gateFor(ref, rule, applies, s.logger)
	if err != nil {
		return err
	}

	scans, gates := len(scanners) > 0, gate.CanFail()
	switch {
	case !scans && !gates:
		return nil
	case !scans:
		return errors.New("--fail-on needs --scan <type>: a pull always scans fresh, never trusting the reports a package carries")
	case !gates:
		return errors.New("--scan needs --fail-on (or a matching rule's) to refuse anything; to just scan, run \"bomify security scan\" after pulling")
	}

	// The publisher's VEX applies first, so the rule's stored VEX wins where
	// they disagree.
	verify := s.verify
	if _, verifies := s.policy.For(ref); !verifies {
		verify = nil
	}
	gate.VEX = security.CombineVEX(security.PublishedVEX(ctx, target, ref, manifest, verify, s.logger), gate.VEX)

	bom, err := sbom.LoadBytes(sbomData)
	if err != nil {
		return fmt.Errorf("parse sbom: %w", err)
	}
	components := sbom.Components(bom.Components)

	plugins, err := findScanners(scanners)
	if err != nil {
		return err
	}
	log := s.logger.With("reference", ref)
	// The package's layers are written by now, so a scanner that scans a
	// type from files gets them.
	result, err := security.ScanAll(plugins, components, security.ScanOptions{Concurrency: s.concurrency, ContentDir: dataDir}, log)
	if err != nil {
		return err
	}
	if err := checkGate(s.w, log, gate, result); err != nil {
		return err
	}
	s.collected = append(s.collected, result.Reports...)
	return nil
}
