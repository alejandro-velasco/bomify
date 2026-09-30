package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"text/tabwriter"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
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

const securityScanLong = `Scan resolves <tag> to a package a prior "bomify build" (or "bomify
pull"/"bomify load") recorded locally, then scans every component that
package's SBOM describes through a single "bomify-plugin-<type>" binary —
<type> names the scanning tool itself (e.g. "grype"), not a purl type or
deployment medium, since any scanner can in principle scan any component.

bomify first asks the plugin, once, which component purl types and scan
categories it supports ("security supported-components"). Any component
whose purl type isn't in that list is skipped; every other component is
scanned via "security scan --purl <purl>", once per component, up to
--concurrency at a time: the same per-component, concurrent dispatch
"bomify build"/"bomify distribute" use, just for scanning instead of
pulling/pushing.

Each component's result is written as its own CycloneDX vulnerability
report, <data-dir>/vulnerabilities/<purl-hash>.json — keyed by the same
purl hash as that component's pull manifest and layer, so a component
shared by two packages shares one report too, and scanning either
package refreshes it for both. A report's metadata component is the
scanned component itself; for a component the plugin had to unpack to
scan at all (e.g. cataloging an OCI image's contents), the pieces it
found are the report's top-level components, and each vulnerability's
"affects" names the specific piece(s) affected. See
plugins/SECURITY-CONTRACT.md for the full contract.

--fail-on makes the scan exit non-zero if any vulnerability found is at
or above the given severity (info, low, medium, high, or critical),
printing a table of them to stderr; a vulnerability's severity is the
highest any of its ratings gives it, and one rated only "none" or
"unknown" never fails. --ignore (repeatable) exempts specific
vulnerability IDs for this scan only. --vex (repeatable) names an
OpenVEX, CSAF, or CycloneDX VEX document: a vulnerability it says doesn't
affect the component it was found in ("not_affected", "false_positive")
or was fixed there ("fixed", "resolved") doesn't fail the scan, and is
logged as exempted instead. For a vulnerability found in an image, every
package it affects there must be exempted. Without --fail-on, the most
specific "bomify security policy" rule matching <tag> decides the
threshold instead, if any does, and that rule's stored VEX documents
always apply alongside --vex, which reads the given file as it is now;
--skip-gate ignores the rule. Reports
are written either way.`

const securityScanExample = `  # Scan the package tagged myapp:latest for vulnerabilities with grype
  bomify security scan grype myapp:latest

  # Scan up to 4 components concurrently
  bomify security scan grype myapp:latest --concurrency 4

  # Fail on anything high or critical, except one accepted CVE
  bomify security scan grype myapp:latest --fail-on high --ignore CVE-2024-1234`

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

	path, err := plugin.Find(plugin.Dir(dataDir), opts.scanType)
	if err != nil {
		return err
	}

	sbomPath := build.ManifestPath(dataDir, sbomHash)
	bom, err := sbom.Load(sbomPath)
	if err != nil {
		return fmt.Errorf("load sbom: %w", err)
	}
	var components []cdx.Component
	if bom.Components != nil {
		components = *bom.Components
	}
	logger.Info("loaded sbom", "path", sbomPath, "components", len(components), "concurrency", opts.concurrency)

	reports, err := security.Scan(path, opts.scanType, components, opts.concurrency, logger)
	if err != nil {
		return err
	}

	for _, r := range reports {
		reportPath, err := security.WriteReport(dataDir, r.Component, r.Report)
		if err != nil {
			return err
		}
		logger.Debug("report written", "purl", r.Component.PackageURL, "path", reportPath)
	}

	return checkGate(cmd.ErrOrStderr(), logger, gate, reports)
}

const securityPruneShort = "Delete stale vulnerability report referrers of a package in a registry"

const securityPruneLong = `Prune deletes all but the newest --keep vulnerability report referrers
attached to the package <ref> resolves to in its registry, each along
with anything referring to it in turn (typically its signature). The
package itself, its own signatures, and anything else attached to it are
left alone.

"bomify push" already does this after attaching new reports (see its
--keep-reports); prune is for retrying that when it couldn't, or for
cleaning up a package without pushing it again. Unlike push, prune fails
if any stale referrer couldn't be deleted — e.g. because the registry
refuses manifest deletes altogether.`

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

const securityPolicyCreateLong = `Create adds a rule to <data-dir>/conf/scan.json setting the scanning
policy for every package whose reference matches --match: the scanning
plugin (bomify-plugin-<scanner>) that scans it, and — with --fail-on —
the severity at or above which its vulnerabilities fail the scan.
--match is a
"/"-separated prefix of the package's repository — its reference
without a tag or digest, e.g. "registry.example.com",
"registry.example.com/team", or "registry.example.com/team/app" —
matched at segment boundaries; omitting it makes the rule apply to
every package. When more than one rule matches, the one with the
longer --match wins. Running create again for the same --match
replaces that rule.

--vex (repeatable) names a VEX document in the data directory's managed
store (see "bomify security vex add") whose "not affected"/"fixed"
statements exempt a matching package's vulnerabilities from --fail-on.
Rules refer to documents by name, never by path, so a rule keeps
working however the files it was built from move, and re-adding a
document under the same name updates every rule using it. Rules have
no list of bare vulnerability IDs to ignore: a standing exemption
belongs in a VEX document, which says which component it applies to
and why. For a one-off, use "bomify security scan --ignore".

"bomify security scan" applies a matching rule's --fail-on when given
no --fail-on of its own, always applies its VEX documents alongside any
--vex of its own, and ignores rules entirely with --skip-gate.

--on (comma-separated or repeatable) also makes a matching package get
scanned with <scanner> and gated automatically at those lifecycle hooks:
"build" (after "bomify build" records it), "push" (before "bomify push"
or "bomify save" sends it anywhere), and "pull" (before "bomify pull"
or "bomify load" writes anything of it). Without --on, the rule only
applies to "bomify security scan". Each of those commands' --scan and
--fail-on override the rule, and --skip-scan ignores it.`

const securityPolicyCreateExample = `  # Fail any scan of a team's packages on high or critical vulnerabilities
  bomify security policy create grype --match registry.example.com/team --fail-on high

  # ...exempting whatever the team's VEX document shows doesn't affect it
  bomify security vex add team team.openvex.json
  bomify security policy create grype --match registry.example.com/team --fail-on high --vex team

  # ...and scan and gate them automatically before they're pushed or pulled
  bomify security policy create grype --match registry.example.com/team --fail-on high --on push,pull

  # Scan every other package with grype, never failing
  bomify security policy create grype`

func securityPolicyCreateCmd() *cobra.Command {
	var rule security.Rule

	cmd := &cobra.Command{
		Use:     "create <scanner>",
		Short:   securityPolicyCreateShort,
		Long:    securityPolicyCreateLong,
		Example: securityPolicyCreateExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rule.Scanner = args[0]
			if err := security.SetRule(dataDir, rule); err != nil {
				return fmt.Errorf("security policy create: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&rule.Match, "match", "", "apply to packages whose repository starts with this \"/\"-separated prefix; default applies to every package")
	cmd.Flags().StringVar(&rule.FailOn, "fail-on", "", "fail on any vulnerability at or above this severity (info, low, medium, high, critical); default never fails")
	cmd.Flags().StringSliceVar(&rule.On, "on", nil, "lifecycle hooks to scan and gate matching packages at automatically: build, push (and save), pull (and load); default none")
	cmd.Flags().StringArrayVar(&rule.VEX, "vex", nil, "the name of a stored VEX document (see \"bomify security vex add\") exempting vulnerabilities it shows don't affect the package (repeatable)")

	return cmd
}

const securityPolicyListShort = "List vulnerability scanning policy rules"

const securityPolicyListLong = `List prints every rule recorded in <data-dir>/conf/scan.json. MATCH
prints "*" for a rule that omitted it, meaning it applies to every
package, FAIL-ON prints "-" for a rule that never fails, VEX lists the
names of each rule's stored VEX documents, and ON the lifecycle hooks
it scans at automatically ("-" for none).`

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
	rules, err := security.ReadConfig(dataDir)
	if err != nil {
		return err
	}

	// Display order only — unrelated to the specificity ranking used
	// when rules are matched against a reference.
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Match < rules[j].Match })

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "MATCH\tSCANNER\tFAIL-ON\tVEX\tON")
	for _, rule := range rules {
		failOn := rule.FailOn
		if failOn == "" {
			failOn = "-"
		}
		on := strings.Join(rule.On, ",")
		if on == "" {
			on = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", wildcardOr(rule.Match), rule.Scanner, failOn, strings.Join(rule.VEX, ","), on)
	}

	return w.Flush()
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
	cmd := &cobra.Command{
		Use:   "vex",
		Short: securityVEXShort,
	}

	cmd.AddCommand(securityVEXAddCmd())
	cmd.AddCommand(securityVEXListCmd())
	cmd.AddCommand(securityVEXRemoveCmd())

	return cmd
}

const securityVEXAddShort = "Add or replace a VEX document in the managed store"

const securityVEXAddLong = `Add copies the VEX document at <file> — OpenVEX, CSAF, or CycloneDX
VEX — into <data-dir>/vex/ under <name>, for "bomify security policy
create --vex <name>" to refer to. The document is checked first, and
stored by its content hash: later edits to <file> have no effect until
it's added again, so a rule's exemptions only ever change when someone
re-adds its documents, and every scan decision traces back to an exact
document. Adding under an existing <name> replaces it for every rule
that uses it.

"bomify security scan --vex <file>" reads a file directly instead, as
it is at that moment, without the store.`

const securityVEXAddExample = `  # Store the team's OpenVEX document as "team"
  bomify security vex add team vex/team.openvex.json

  # After editing it, add it again to update every rule using "team"
  bomify security vex add team vex/team.openvex.json`

func securityVEXAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "add <name> <file>",
		Short:   securityVEXAddShort,
		Long:    securityVEXAddLong,
		Example: securityVEXAddExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, err := security.AddVEX(dataDir, args[0], args[1])
			if err != nil {
				return fmt.Errorf("security vex add: %w", err)
			}
			logging.FromContext(cmd.Context()).Info("VEX document stored", "name", entry.Name, "sha256", entry.SHA256, "source", entry.Source)
			return nil
		},
	}
}

const securityVEXListShort = "List the VEX documents in the managed store"

const securityVEXListLong = `List prints every document in <data-dir>/vex/: its name, the content
hash it's stored under, when it was added, and the file it was copied
from (never read again).`

const securityVEXListExample = `  # See every stored VEX document
  bomify security vex list`

func securityVEXListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   securityVEXListShort,
		Long:    securityVEXListLong,
		Example: securityVEXListExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := security.ListVEX(dataDir)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "NAME\tSHA256\tADDED\tSOURCE")
			for _, e := range entries {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Name, e.SHA256[:12], e.Added, e.Source)
			}
			return w.Flush()
		},
	}
}

const securityVEXRemoveShort = "Remove a VEX document from the managed store"

const securityVEXRemoveLong = `Remove drops <name> from <data-dir>/vex/, deleting its stored copy
unless another name refers to the same content. It refuses while any
"bomify security policy" rule still lists <name>, so no rule is left
referring to a document that no longer exists.`

const securityVEXRemoveExample = `  # Remove the document stored as "team"
  bomify security vex remove team`

func securityVEXRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Short:   securityVEXRemoveShort,
		Long:    securityVEXRemoveLong,
		Example: securityVEXRemoveExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := security.RemoveVEX(dataDir, args[0]); err != nil {
				return fmt.Errorf("security vex remove: %w", err)
			}
			return nil
		},
	}
}
