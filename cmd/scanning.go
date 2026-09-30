package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/signature"
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
	cmd.Flags().StringArrayVar(&f.vex, "vex", nil, "an OpenVEX, CSAF, or CycloneDX VEX document whose not-affected/fixed statements exempt vulnerabilities from failing (repeatable); added to a matching rule's")
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

// scanFlags are the flags that scan and gate a package as pull or load
// restores it: --scan <type>, --fail-on, and --skip-scan.
type scanFlags struct {
	scanner string
	gateFlags
}

func (f *scanFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.scanner, "scan", "", "scan the package's components with the bomify-plugin-<type> scanner before anything is written (e.g. grype), refusing it if --fail-on is met; overrides a matching \"bomify security policy\" rule's scanner")
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
	// policy and verify are the pull's signature verification: the
	// package's publisher's VEX counts only where they verify it.
	policy signature.Policy
	verify transfer.Verifier
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
//
// The gate also honors VEX documents the package's publisher attached
// (see publisherVEX) — applied before the rule's own, so local VEX wins
// where they disagree.
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

	published, err := s.publisherVEX(ctx, target, ref, manifest)
	if err != nil {
		return err
	}
	gate.VEX = security.CombineVEX(published, gate.VEX)

	bom, err := sbom.LoadBytes(sbomData)
	if err != nil {
		return fmt.Errorf("parse sbom: %w", err)
	}
	var components []cdx.Component
	if bom.Components != nil {
		components = *bom.Components
	}

	path, err := plugin.Find(plugin.Dir(dataDir), scanner)
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

// publisherVEX loads the VEX documents attached to the package ref
// resolved to (see security.AttachVEX) — but only where this pull
// verifies signatures, and only those whose own signature verifies:
// otherwise anyone who can push to the repository could silence any
// finding. Documents it can't trust are skipped with a warning, never
// failing the pull; they only ever exempt, so skipping one is the safe
// side.
func (s *pullScanHook) publisherVEX(ctx context.Context, target oras.ReadOnlyTarget, ref string, manifest ocispec.Descriptor) (*security.VEX, error) {
	referrers, err := security.VEXReferrers(ctx, target, manifest)
	if err != nil {
		s.logger.Warn("can't list the package's VEX documents; ignoring them", "reference", ref, "error", err)
		return nil, nil
	}
	if len(referrers) == 0 {
		return nil, nil
	}
	if !s.policy.Verifies(ref) || s.verify == nil {
		s.logger.Warn("ignoring the package's VEX documents: they only count on a pull that verifies signatures (--verify, or a \"bomify trust\" rule)", "reference", ref, "documents", len(referrers))
		return nil, nil
	}

	var docs []security.VEXDocument
	for _, referrer := range referrers {
		if err := s.verify(ctx, target, ref, referrer); err != nil {
			s.logger.Warn("ignoring an unverified VEX document", "reference", ref, "document", referrer.Digest.String(), "error", err)
			continue
		}
		doc, err := security.FetchVEX(ctx, target, referrer)
		if err != nil {
			s.logger.Warn("ignoring a VEX document that can't be fetched", "reference", ref, "document", referrer.Digest.String(), "error", err)
			continue
		}
		docs = append(docs, doc)
	}
	return security.LoadVEXDocuments(docs, "published with "+ref+": ")
}

// publishVEX reads each of args — the name of a document in the managed
// VEX store (see "bomify security vex add"), or else a file — for push
// or save to attach to the package (see security.AttachVEX), checking
// each loads first.
func publishVEX(args []string) ([]security.VEXDocument, error) {
	if len(args) == 0 {
		return nil, nil
	}
	stored, err := security.ListVEX(dataDir)
	if err != nil {
		return nil, err
	}

	var docs []security.VEXDocument
	for _, arg := range args {
		path, name := arg, filepath.Base(arg)
		if i := slices.IndexFunc(stored, func(e security.StoredVEX) bool { return e.Name == arg }); i >= 0 {
			path, name = security.VEXPath(dataDir, stored[i].SHA256), arg
		}
		if _, err := security.LoadVEX([]string{path}); err != nil {
			return nil, fmt.Errorf("--vex %s: %w", arg, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("--vex %s: %w", arg, err)
		}
		docs = append(docs, security.VEXDocument{Name: name, Data: data})
	}
	return docs, nil
}
