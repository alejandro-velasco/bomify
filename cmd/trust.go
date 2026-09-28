package cmd

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/signature"
)

const trustShort = "Manage signature verification rules for bomify pull and load"

func trustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: trustShort,
	}

	cmd.AddCommand(trustCreateCmd())
	cmd.AddCommand(trustListCmd())
	cmd.AddCommand(trustRemoveCmd())

	return cmd
}

const trustCreateShort = "Create or update a signature verification rule"

const trustCreateLong = `Create adds a rule to <data-dir>/conf/trust.json requiring every
package whose reference matches --match to carry a signature the
<verifier> signing plugin (bomify-plugin-<verifier>) verifies before
"bomify pull" or "bomify load" restore it. --match is a "/"-separated
prefix of the package's repository — its reference without a tag or
digest, e.g. "registry.example.com", "registry.example.com/team", or
"registry.example.com/team/app" — matched at segment boundaries;
omitting it makes the rule apply to every package. When more than one
rule matches, the one with the longer --match wins. Running create
again for the same --match replaces that rule.

Each --option (key=value) is passed through, unparsed, to the plugin's
"signature verify" — typically naming which key or identity it should
trust for packages matching this rule.

An explicit "--verify" on pull/load takes precedence over every rule,
and "--insecure-skip-verify" bypasses them.`

const trustCreateExample = `  # Require packages from a team's repositories to be signed with its cosign key
  bomify trust create cosign --match registry.example.com/team --option key=team.pub

  # Require every package to be signed by a keyless identity
  bomify trust create cosign \
    --option certificate-identity=release@example.com \
    --option certificate-oidc-issuer=https://accounts.google.com`

type trustCreateOptions struct {
	match   string
	options []string
}

func trustCreateCmd() *cobra.Command {
	opts := &trustCreateOptions{}

	cmd := &cobra.Command{
		Use:     "create <verifier>",
		Short:   trustCreateShort,
		Long:    trustCreateLong,
		Example: trustCreateExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateOptions("--option", opts.options); err != nil {
				return fmt.Errorf("trust create: %w", err)
			}
			if err := signature.SetRule(dataDir, opts.match, args[0], opts.options); err != nil {
				return fmt.Errorf("trust create: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.match, "match", "", "apply to packages whose repository starts with this \"/\"-separated prefix; default applies to every package")
	cmd.Flags().StringArrayVar(&opts.options, "option", nil, "a key=value option passed through to the verifier plugin (repeatable)")

	return cmd
}

const trustListShort = "List signature verification rules"

const trustListLong = `List prints every rule recorded in <data-dir>/conf/trust.json. MATCH
prints "*" for a rule that omitted it, meaning it applies to every
package.`

const trustListExample = `  # See every configured rule
  bomify trust list`

func trustListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   trustListShort,
		Long:    trustListLong,
		Example: trustListExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrustList(cmd)
		},
	}

	return cmd
}

func runTrustList(cmd *cobra.Command) error {
	rules, err := signature.Read(dataDir)
	if err != nil {
		return err
	}

	// Display order only — unrelated to the specificity ranking used
	// when rules are matched against a reference.
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Match < rules[j].Match })

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "MATCH\tVERIFIER\tOPTIONS")
	for _, rule := range rules {
		fmt.Fprintf(w, "%s\t%s\t%s\n", wildcardOr(rule.Match), rule.Verifier, strings.Join(rule.Options, ","))
	}

	return w.Flush()
}

const trustRemoveShort = "Remove a signature verification rule"

const trustRemoveLong = `Remove drops the rule matching --match exactly (as "bomify trust
list" prints it) from <data-dir>/conf/trust.json.`

const trustRemoveExample = `  # Remove the rule for a team's repositories
  bomify trust remove --match registry.example.com/team

  # Remove the rule applying to every package (no --match)
  bomify trust remove`

func trustRemoveCmd() *cobra.Command {
	var match string

	cmd := &cobra.Command{
		Use:     "remove",
		Short:   trustRemoveShort,
		Long:    trustRemoveLong,
		Example: trustRemoveExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := signature.RemoveRule(dataDir, match); err != nil {
				return fmt.Errorf("trust remove: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&match, "match", "", "the rule's match prefix, exactly as \"bomify trust list\" prints it (empty for a rule with no --match)")

	return cmd
}
