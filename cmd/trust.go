package cmd

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/rules"
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
	cmd.AddCommand(trustKeyCmd())

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

Each --key-option (option=name) instead names a public key in the data
directory's managed key store (see "bomify trust key add"): the plugin
gets "--option <option>=<path of the stored copy>". The rule then keeps
working however the original key file moves, travels with the data
directory, and only changes when someone adds the key again. Which
option takes a key file is up to the plugin — sigstore's is "key". The
same option can't be given both ways.

An explicit "--verify" on pull/load takes precedence over every rule,
and "--insecure-skip-verify" bypasses them.`

const trustCreateExample = `  # Require packages from a team's repositories to be signed with its cosign key
  bomify trust create sigstore --match registry.example.com/team --option key=team.pub

  # Require every package to be signed with the organization's key
  bomify trust create sigstore --option key=org.pub

  # The same, with the key kept in the managed key store
  bomify trust key add org org.pub
  bomify trust create sigstore --key-option key=org`

type trustCreateOptions struct {
	match      string
	options    []string
	keyOptions []string
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
			keyOptions, err := parseKeyOptions(opts.keyOptions)
			if err != nil {
				return fmt.Errorf("trust create: %w", err)
			}
			rule := signature.Rule{Match: opts.match, Verifier: args[0], Options: opts.options, KeyOptions: keyOptions}
			if err := signature.SetRule(dataDir, rule); err != nil {
				return fmt.Errorf("trust create: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.match, "match", "", "apply to packages whose repository starts with this \"/\"-separated prefix; default applies to every package")
	cmd.Flags().StringArrayVar(&opts.options, "option", nil, "a key=value option passed through to the verifier plugin (repeatable)")
	cmd.Flags().StringArrayVar(&opts.keyOptions, "key-option", nil, "an option=name pair: pass the verifier plugin option=<path of the stored key name> (see \"bomify trust key add\"; repeatable)")

	return cmd
}

// parseKeyOptions turns --key-option "option=name" pairs into a map,
// rejecting malformed pairs and an option given twice.
func parseKeyOptions(pairs []string) (map[string]string, error) {
	if err := validateOptions("--key-option", pairs); err != nil {
		return nil, err
	}
	if len(pairs) == 0 {
		return nil, nil
	}
	keyOptions := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		option, name, _ := strings.Cut(pair, "=")
		if _, dup := keyOptions[option]; dup {
			return nil, fmt.Errorf("--key-option %q given more than once", option)
		}
		keyOptions[option] = name
	}
	return keyOptions, nil
}

const trustListShort = "List signature verification rules"

const trustListLong = `List prints every rule recorded in <data-dir>/conf/trust.json. MATCH
prints "*" for a rule that omitted it, meaning it applies to every
package. KEY-OPTIONS lists each option=name pair naming a stored key.`

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
	config, err := signature.Read(dataDir)
	if err != nil {
		return err
	}

	// Display order only — unrelated to the specificity ranking used
	// when rules are matched against a reference.
	sort.SliceStable(config, func(i, j int) bool { return config[i].Match < config[j].Match })

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "MATCH\tVERIFIER\tOPTIONS\tKEY-OPTIONS")
	for _, rule := range config {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", rules.Display(rule.Match), rule.Verifier, strings.Join(rule.Options, ","), formatKeyOptions(rule.KeyOptions))
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

// formatKeyOptions renders key options as sorted "option=name" pairs.
func formatKeyOptions(keyOptions map[string]string) string {
	pairs := make([]string, 0, len(keyOptions))
	for option, name := range keyOptions {
		pairs = append(pairs, option+"="+name)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

const trustKeyShort = "Manage the public keys trust rules refer to"

func trustKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: trustKeyShort,
	}

	cmd.AddCommand(trustKeyAddCmd())
	cmd.AddCommand(trustKeyListCmd())
	cmd.AddCommand(trustKeyRemoveCmd())

	return cmd
}

const trustKeyAddShort = "Add or replace a public key in the managed key store"

const trustKeyAddLong = `Add copies the PEM file at <file> into <data-dir>/keys/ under <name>,
for "bomify trust create --key-option <option>=<name>" to refer to. Only
public material is accepted: every PEM block must be a CERTIFICATE,
PUBLIC KEY, or RSA PUBLIC KEY that actually parses. A private key is
refused, so a signing key is never copied into the data directory by
mistake (sign with --sign-option instead), and a corrupt or wrong file
fails here rather than on a later pull. Formats other than X.509-style
PEM (e.g. an SSH or minisign public key) can't be stored; pass those
with --option instead.

The key is stored by its content hash: later edits to <file> have no
effect until it's added again, so a rule's trust only changes when
someone re-adds its keys. Adding under an existing <name> replaces it
for every rule that uses it — e.g. to rotate a key.

"--option key=<path>", on "bomify trust create" and as --verify-option,
still reads a key file directly, without the store.`

const trustKeyAddExample = `  # Store the team's cosign public key as "team"
  bomify trust key add team keys/team.pub

  # Rotate it: every rule using "team" now trusts the new key
  bomify trust key add team keys/team-2026.pub`

func trustKeyAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "add <name> <file>",
		Short:   trustKeyAddShort,
		Long:    trustKeyAddLong,
		Example: trustKeyAddExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, err := signature.AddKey(dataDir, args[0], args[1])
			if err != nil {
				return fmt.Errorf("trust key add: %w", err)
			}
			logging.FromContext(cmd.Context()).Info("key stored", "name", entry.Name, "sha256", entry.SHA256, "source", entry.Source)
			return nil
		},
	}
}

const trustKeyListShort = "List the public keys in the managed key store"

const trustKeyListLong = `List prints every key in <data-dir>/keys/: its name, the content hash
it's stored under, when it was added, and the file it was copied from
(never read again).`

const trustKeyListExample = `  # See every stored key
  bomify trust key list`

func trustKeyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   trustKeyListShort,
		Long:    trustKeyListLong,
		Example: trustKeyListExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := signature.ListKeys(dataDir)
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

const trustKeyRemoveShort = "Remove a public key from the managed key store"

const trustKeyRemoveLong = `Remove drops <name> from <data-dir>/keys/, deleting its stored copy
unless another name refers to the same content. It refuses while any
"bomify trust" rule still refers to <name>, so no rule is left
referring to a key that no longer exists.`

const trustKeyRemoveExample = `  # Remove the key stored as "team"
  bomify trust key remove team`

func trustKeyRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Short:   trustKeyRemoveShort,
		Long:    trustKeyRemoveLong,
		Example: trustKeyRemoveExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := signature.RemoveKey(dataDir, args[0]); err != nil {
				return fmt.Errorf("trust key remove: %w", err)
			}
			return nil
		},
	}
}
