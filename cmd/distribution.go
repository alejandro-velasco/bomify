package cmd

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/distribution"
)

const distributionShort = "Manage remote-endpoint rules for bomify distribute"

func distributionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "distribution",
		Short: distributionShort,
	}

	cmd.AddCommand(distributionCreateCmd())
	cmd.AddCommand(distributionListCmd())
	cmd.AddCommand(distributionRemoveCmd())

	return cmd
}

const distributionCreateShort = "Create or update a remote-endpoint rule"

const distributionCreateLong = `Create adds a rule to <data-dir>/conf/distribution.json, the file
"bomify distribute" falls back to for any component not given a
matching --remote. A rule matches a component by --type (a plugin
kind, e.g. "oci" or "helm") and/or --match (a "/"-separated prefix of
the component's origin — its plugin's own report of where it comes
from, e.g. "docker.io", "docker.io/myorg", or "docker.io/myorg/myrepo");
either or both can be omitted to widen the rule, down to a single
catch-all rule matching everything. When more than one rule matches a
component, the one with the longer --match wins, and a matching --type
breaks a tie between two equally specific matches. Running create
again for the same --type/--match pair overwrites its endpoint.

A rule with a non-empty --match acts as a mirror, not just a lookup: whatever
of the component's origin comes after the matched prefix is carried
over onto <endpoint>, so distinct repositories under that prefix still
land at distinct destinations instead of all colliding on one endpoint
(e.g. --match docker.io/myorg against origin docker.io/myorg/app
resolves to <endpoint>/app). A rule with no --match has nothing to
carry over, so <endpoint> is used exactly as given — it's up to the
component's own plugin to decide what to publish under it.`

const distributionCreateExample = `  # Fall back to this OCI registry for any OCI component
  bomify distribution create registry.example.com --type oci

  # Mirror anything from docker.io/myorg under a new registry, keeping
  # the rest of each repository's path: docker.io/myorg/app becomes
  # mirror.example.com/myorg/app
  bomify distribution create mirror.example.com/myorg --type oci --match docker.io/myorg

  # Match by origin alone, regardless of plugin kind
  bomify distribution create mirror.example.com --match docker.io

  # A catch-all fallback for anything else
  bomify distribution create fallback.example.com`

type distributionCreateOptions struct {
	ruleType string
	match    string
}

func distributionCreateCmd() *cobra.Command {
	opts := &distributionCreateOptions{}

	cmd := &cobra.Command{
		Use:     "create <endpoint>",
		Short:   distributionCreateShort,
		Long:    distributionCreateLong,
		Example: distributionCreateExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := distribution.SetRule(dataDir, opts.ruleType, opts.match, args[0]); err != nil {
				return fmt.Errorf("distribution create: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.ruleType, "type", "", "match components of this plugin kind only (e.g. oci, helm, generic); default matches any kind")
	cmd.Flags().StringVar(&opts.match, "match", "", "match components whose origin (repository_url/download_url) starts with this \"/\"-separated prefix; default matches any origin")

	return cmd
}

const distributionListShort = "List remote-endpoint rules"

const distributionListLong = `List prints every rule recorded in <data-dir>/conf/distribution.json,
most specific first — see "bomify distribution create" for how rules
are matched and ranked. TYPE or MATCH prints "*" for a rule that
omitted it, meaning it matches any kind or any origin there.`

const distributionListExample = `  # See every configured rule
  bomify distribution list`

func distributionListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   distributionListShort,
		Long:    distributionListLong,
		Example: distributionListExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDistributionList(cmd)
		},
	}

	return cmd
}

func runDistributionList(cmd *cobra.Command) error {
	rules, err := distribution.Read(dataDir)
	if err != nil {
		return err
	}

	// Display order only (alphabetical by type, then match) — unrelated to
	// the specificity ranking used when rules are matched against a component.
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Type != rules[j].Type {
			return rules[i].Type < rules[j].Type
		}
		return rules[i].Match < rules[j].Match
	})

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "TYPE\tMATCH\tENDPOINT")
	for _, rule := range rules {
		fmt.Fprintf(w, "%s\t%s\t%s\n", wildcardOr(rule.Type), wildcardOr(rule.Match), rule.Endpoint)
	}

	return w.Flush()
}

// wildcardOr renders an empty rule field (matching any value) as "*".
func wildcardOr(field string) string {
	if field == "" {
		return "*"
	}
	return field
}

const distributionRemoveShort = "Remove a remote-endpoint rule"

const distributionRemoveLong = `Remove drops the rule matching --type/--match exactly (as
"bomify distribution list" prints them) from
<data-dir>/conf/distribution.json.`

const distributionRemoveExample = `  # Remove the docker.io/myorg-specific oci rule
  bomify distribution remove --type oci --match docker.io/myorg

  # Remove the catch-all rule (no --type, no --match)
  bomify distribution remove`

func distributionRemoveCmd() *cobra.Command {
	opts := &distributionCreateOptions{}

	cmd := &cobra.Command{
		Use:     "remove",
		Short:   distributionRemoveShort,
		Long:    distributionRemoveLong,
		Example: distributionRemoveExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := distribution.RemoveRule(dataDir, opts.ruleType, opts.match); err != nil {
				return fmt.Errorf("distribution remove: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.ruleType, "type", "", "the rule's plugin kind, exactly as \"bomify distribution list\" prints it (empty for a rule with no --type)")
	cmd.Flags().StringVar(&opts.match, "match", "", "the rule's match prefix, exactly as \"bomify distribution list\" prints it (empty for a rule with no --match)")

	return cmd
}
