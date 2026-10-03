package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/rules"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
	"github.com/alejandro-velasco/bomify/internal/table"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

const securityShort = "Security scanning commands"

func securityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: securityShort,
	}

	cmd.AddCommand(securityScanCmd())
	cmd.AddCommand(securityPruneCmd())
	cmd.AddCommand(securityPolicyCmd())
	cmd.AddCommand(securityVEXCmd())

	return cmd
}

const securityScanShort = "Scan a built package's components for vulnerabilities via a security scanning plugin"

const securityScanLong = `Scan scans every component of the local package <tag> with
bomify-plugin-<type> (a scanner such as grype) and writes one CycloneDX
vulnerability report per component to <data-dir>/vulnerabilities/,
shared by every package containing that component. Each scanner keeps
its own report of a component, so scanning with another scanner adds to
this one's rather than replacing it. Components of purl
types the scanner doesn't support are skipped, and listed on stderr.

--fail-on takes comma-separated conditions that exit non-zero, printing
what failed to stderr. Reports are written either way.
  - A severity (info, low, medium, high, critical): any vulnerability at
    or above it.
  - "unscanned": any component the scanner skipped, so nothing passes
    unchecked. Skipped components are listed on stderr either way.
  --ignore (repeatable) exempts vulnerability IDs for this scan only.
  --vex (repeatable) reads an OpenVEX, CSAF, or CycloneDX VEX file; a
  vulnerability it marks not affected or fixed doesn't fail the scan.
  For an image, every affected package in it must be exempted.

Without --fail-on, the most specific matching "bomify security policy"
rule's conditions apply; --fail-on replaces them all. The rule's stored
VEX always applies alongside --vex. --skip-gate ignores the rule's
conditions.`

const securityScanExample = `  # Scan the package tagged myapp:latest for vulnerabilities with grype
  bomify security scan grype myapp:latest

  # Scan up to 4 components concurrently
  bomify security scan grype myapp:latest --concurrency 4

  # Fail on anything high or critical, except one accepted CVE
  bomify security scan grype myapp:latest --fail-on high --ignore CVE-2024-1234

  # Also fail if grype skipped any component
  bomify security scan grype myapp:latest --fail-on high,unscanned`

type securityScanOptions struct {
	scanType    string
	tag         string
	concurrency int
	gate        gateFlags
}

func securityScanCmd() *cobra.Command {
	opts := &securityScanOptions{}

	cmd := &cobra.Command{
		Use:     "scan <type> <tag>",
		Short:   securityScanShort,
		Long:    securityScanLong,
		Example: securityScanExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.scanType, opts.tag = args[0], args[1]
			if err := runSecurityScan(cmd, opts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("security scan: %w", err)
			}
			return nil
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 1 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeLocalTags(cmd, args, toComplete)
		},
	}

	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 1, "number of components to scan concurrently")
	opts.gate.register(cmd)

	return cmd
}

func runSecurityScan(cmd *cobra.Command, opts *securityScanOptions, logger *slog.Logger) error {
	sbomHash, err := build.ResolveTag(dataDir, opts.tag)
	if err != nil {
		return err
	}

	// Resolved before scanning, so a bad flag or rule fails fast.
	gate, err := opts.gate.gate(opts.tag, logger)
	if err != nil {
		return err
	}

	path, err := plugin.Find(layout.Plugins(dataDir), opts.scanType, pluginlib.SecurityContract)
	if err != nil {
		return err
	}

	sbomPath := layout.Manifest(dataDir, sbomHash)
	bom, err := sbom.Load(sbomPath)
	if err != nil {
		return fmt.Errorf("load sbom: %w", err)
	}
	components := sbom.Components(bom.Components)
	logger.Info("loaded sbom", "path", sbomPath, "components", len(components), "concurrency", opts.concurrency)

	reports, skipped, err := security.Scan(path, opts.scanType, components, opts.concurrency, logger)
	if err != nil {
		return err
	}

	for _, r := range reports {
		reportPath, err := security.WriteReport(dataDir, r)
		if err != nil {
			return err
		}
		logger.Debug("report written", "purl", r.Component.PackageURL, "path", reportPath)
	}

	return checkGate(cmd.ErrOrStderr(), logger, gate, opts.scanType, len(components), reports, skipped)
}

const securityPruneShort = "Delete stale vulnerability report referrers of a package in a registry"

const securityPruneLong = `Prune deletes all but the newest --keep vulnerability report referrers
of the package <ref> in its registry, each with its signature. Nothing
else attached to the package is touched.

"bomify push" already prunes; use this to retry when the registry
refused, or to clean up without pushing. Unlike push, prune fails if
any deletion fails.`

const securityPruneExample = `  # Keep only the newest vulnerability reports of a pushed package
  bomify security prune registry.example.com/myapp:latest

  # Keep the three newest
  bomify security prune registry.example.com/myapp:latest --keep 3`

func securityPruneCmd() *cobra.Command {
	var keep int

	cmd := &cobra.Command{
		Use:     "prune <ref>",
		Short:   securityPruneShort,
		Long:    securityPruneLong,
		Example: securityPruneExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keep < 1 {
				return fmt.Errorf("security prune: --keep must be at least 1")
			}
			if err := runSecurityPrune(cmd.Context(), args[0], keep, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("security prune: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&keep, "keep", 1, "number of newest vulnerability report referrers to keep")

	return cmd
}

func runSecurityPrune(ctx context.Context, ref string, keep int, logger *slog.Logger) error {
	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	manifest, err := repo.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", ref, err)
	}

	deleted, err := security.PruneReferrers(ctx, repo, manifest, keep)
	for _, d := range deleted {
		logger.Info("stale referrer deleted", "digest", d.Digest.String(), "artifactType", d.ArtifactType)
	}
	if err != nil {
		return err
	}
	if len(deleted) == 0 {
		logger.Info("nothing to prune", "reference", ref)
	}
	return nil
}

const securityPolicyShort = "Manage vulnerability scanning policy rules"

func securityPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: securityPolicyShort,
	}

	cmd.AddCommand(securityPolicyCreateCmd())
	cmd.AddCommand(securityPolicyListCmd())
	cmd.AddCommand(securityPolicyRemoveCmd())

	return cmd
}

const securityPolicyCreateShort = "Create or update a vulnerability scanning policy rule"

const securityPolicyCreateLong = `Create adds a scan policy rule for packages whose repository starts with
--match (a "/"-separated prefix; omit it to match every package): the
scanner to use and, with --fail-on, what fails a matching package (as
for "bomify security scan": a severity, and/or "unscanned"). The longest
matching --match wins, and creating a rule for the same --match replaces
it.

--vex (repeatable) names documents from "bomify security vex add" that
exempt vulnerabilities. Rules have no ignore list on purpose: a standing
exemption belongs in VEX, which says which component and why. Use
"bomify security scan --ignore" for one-offs.

"bomify security scan" uses a matching rule's --fail-on when given none,
and always applies its VEX.

--on pull also scans and gates matching packages in "bomify pull" and
"bomify load" before anything is written. It requires --fail-on. Without
--on, the rule only applies to "bomify security scan".`

const securityPolicyCreateExample = `  # Fail any scan of a team's packages on high or critical vulnerabilities
  bomify security policy create grype --match registry.example.com/team --fail-on high

  # ...exempting whatever the team's VEX document shows doesn't affect it
  bomify security vex add team team.openvex.json
  bomify security policy create grype --match registry.example.com/team --fail-on high --vex team

  # ...and scan and gate them automatically before they're pulled or loaded
  bomify security policy create grype --match registry.example.com/team --fail-on high --on pull

  # ...also refusing any package with a component grype can't scan
  bomify security policy create grype --match registry.example.com/team --fail-on high,unscanned --on pull

  # Scan every other package with grype, never failing
  bomify security policy create grype`

func securityPolicyCreateCmd() *cobra.Command {
	var rule security.Rule
	var failOn []string

	cmd := &cobra.Command{
		Use:     "create <scanner>",
		Short:   securityPolicyCreateShort,
		Long:    securityPolicyCreateLong,
		Example: securityPolicyCreateExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rule.Scanner = args[0]
			g, err := security.ParseFailOn(failOn)
			if err != nil {
				return fmt.Errorf("security policy create: --fail-on: %w", err)
			}
			if g.FailOn != security.SeverityNone {
				rule.FailOn = g.FailOn.String()
			}
			rule.FailOnUnscanned = g.FailOnUnscanned
			if err := security.SetRule(dataDir, rule); err != nil {
				return fmt.Errorf("security policy create: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&rule.Match, "match", "", "apply to packages whose repository starts with this \"/\"-separated prefix; default applies to every package")
	cmd.Flags().StringSliceVar(&failOn, "fail-on", nil, failOnUsage+"; default never fails")
	cmd.Flags().StringSliceVar(&rule.On, "on", nil, "lifecycle hooks to scan and gate matching packages at automatically: pull (which covers load too); default none")
	cmd.Flags().StringArrayVar(&rule.VEX, "vex", nil, "the name of a stored VEX document (see \"bomify security vex add\") exempting vulnerabilities it shows don't affect the package (repeatable)")

	return cmd
}

const securityPolicyListShort = "List vulnerability scanning policy rules"

const securityPolicyListLong = `List prints every scan policy rule. "*" in MATCH means every package.
FAIL-ON lists what fails a matching package: a severity threshold, and
"unscanned" for components the scanner skipped.
"-" means nothing fails it, or no ON hooks.`

const securityPolicyListExample = `  # See every configured rule
  bomify security policy list`

func securityPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   securityPolicyListShort,
		Long:    securityPolicyListLong,
		Example: securityPolicyListExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecurityPolicyList(cmd)
		},
	}
}

func runSecurityPolicyList(cmd *cobra.Command) error {
	config, err := security.Read(dataDir)
	if err != nil {
		return err
	}

	// Display order only — unrelated to the specificity ranking used
	// when rules are matched against a reference.
	sort.SliceStable(config, func(i, j int) bool { return config[i].Match < config[j].Match })

	rows := make([][]string, 0, len(config))
	for _, rule := range config {
		rows = append(rows, []string{rules.Display(rule.Match), rule.Scanner, dashIfEmpty(failsOn(rule)), strings.Join(rule.VEX, ","), dashIfEmpty(strings.Join(rule.On, ","))})
	}
	return table.Write(cmd.OutOrStdout(), []string{"MATCH", "SCANNER", "FAIL-ON", "VEX", "ON"}, rows)
}

// failsOn lists what fails a package matching rule, for policy list's
// FAIL-ON column: its severity threshold, then "unscanned" with
// FailOnUnscanned, comma-separated. Empty if nothing does.
func failsOn(rule security.Rule) string {
	var conditions []string
	if rule.FailOn != "" {
		conditions = append(conditions, rule.FailOn)
	}
	if rule.FailOnUnscanned {
		conditions = append(conditions, "unscanned")
	}
	return strings.Join(conditions, ",")
}

const securityPolicyRemoveShort = "Remove a vulnerability scanning policy rule"

const securityPolicyRemoveLong = `Remove drops the rule matching --match exactly (as "bomify security
policy list" prints it) from <data-dir>/conf/scan.json.`

const securityPolicyRemoveExample = `  # Remove the rule for a team's repositories
  bomify security policy remove --match registry.example.com/team

  # Remove the rule applying to every package (no --match)
  bomify security policy remove`

func securityPolicyRemoveCmd() *cobra.Command {
	var match string

	cmd := &cobra.Command{
		Use:     "remove",
		Short:   securityPolicyRemoveShort,
		Long:    securityPolicyRemoveLong,
		Example: securityPolicyRemoveExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := security.RemoveRule(dataDir, match); err != nil {
				return fmt.Errorf("security policy remove: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&match, "match", "", "the rule's match prefix, exactly as \"bomify security policy list\" prints it (empty for a rule with no --match)")

	return cmd
}

const securityVEXShort = "Manage the VEX documents scan policy rules refer to"

func securityVEXCmd() *cobra.Command {
	return storeCommand{
		use: "vex", short: securityVEXShort, path: "security vex", noun: "VEX document",
		add: security.AddVEX, list: security.ListVEX, remove: security.RemoveVEX,
		addHelp:    commandHelp{securityVEXAddShort, securityVEXAddLong, securityVEXAddExample},
		listHelp:   commandHelp{securityVEXListShort, securityVEXListLong, securityVEXListExample},
		removeHelp: commandHelp{securityVEXRemoveShort, securityVEXRemoveLong, securityVEXRemoveExample},
	}.command()
}

const securityVEXAddShort = "Add or replace a VEX document in the managed store"

const securityVEXAddLong = `Add stores a copy of the VEX document <file> (OpenVEX, CSAF, or
CycloneDX VEX) under <name>, for "bomify security policy create --vex
<name>". The document is checked first. Later edits to <file> have no
effect until it's added again; adding an existing <name> replaces it for
every rule using it.

"bomify security scan --vex <file>" reads a file directly instead.`

const securityVEXAddExample = `  # Store the team's OpenVEX document as "team"
  bomify security vex add team vex/team.openvex.json

  # After editing it, add it again to update every rule using "team"
  bomify security vex add team vex/team.openvex.json`

const securityVEXListShort = "List the VEX documents in the managed store"

const securityVEXListLong = `List prints every stored VEX document: its name, content hash, when it
was added, and the file it was copied from.`

const securityVEXListExample = `  # See every stored VEX document
  bomify security vex list`

const securityVEXRemoveShort = "Remove a VEX document from the managed store"

const securityVEXRemoveLong = `Remove deletes <name> from the VEX store, and its stored copy unless
another name shares it. It refuses while a "bomify security policy" rule
uses <name>.`

const securityVEXRemoveExample = `  # Remove the document stored as "team"
  bomify security vex remove team`
