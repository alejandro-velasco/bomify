package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/rules"
	"github.com/alejandro-velasco/bomify/internal/signature"
	"github.com/alejandro-velasco/bomify/internal/table"
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

const trustCreateLong = `Create adds a rule requiring packages whose repository starts with
--match (a "/"-separated prefix; omit it to match every package) to
carry a signature that bomify-plugin-<verifier> verifies before "bomify
pull" or "bomify load" restores them. The longest matching --match wins,
and creating a rule for the same --match replaces it.

--option (key=value) is passed to the plugin's verify unparsed, e.g. the
key or identity to trust. --key-option (option=name) instead names a key
from "bomify trust key add"; the plugin receives the stored copy's path
as that option. The same option can't be given both ways.

"--verify" on pull or load overrides every rule, and
"--insecure-skip-verify" bypasses them.`

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

const trustListLong = `List prints every trust rule. "*" in MATCH means every package, and
KEY-OPTIONS lists each option=name pair naming a stored key.`

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

	rows := make([][]string, 0, len(config))
	for _, rule := range config {
		rows = append(rows, []string{rules.Display(rule.Match), rule.Verifier, strings.Join(rule.Options, ","), formatKeyOptions(rule.KeyOptions)})
	}
	return table.Write(cmd.OutOrStdout(), []string{"MATCH", "VERIFIER", "OPTIONS", "KEY-OPTIONS"}, rows)
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
	return storeCommand{
		use: "key", short: trustKeyShort, path: "trust key", noun: "key",
		add: signature.AddKey, list: signature.ListKeys, remove: signature.RemoveKey,
		addHelp:    commandHelp{trustKeyAddShort, trustKeyAddLong, trustKeyAddExample},
		listHelp:   commandHelp{trustKeyListShort, trustKeyListLong, trustKeyListExample},
		removeHelp: commandHelp{trustKeyRemoveShort, trustKeyRemoveLong, trustKeyRemoveExample},
	}.command()
}

const trustKeyAddShort = "Add or replace a public key in the managed key store"

const trustKeyAddLong = `Add stores a copy of the public key or certificate <file> under <name>,
for "bomify trust create --key-option <option>=<name>". Every PEM block
must be a CERTIFICATE, PUBLIC KEY, or RSA PUBLIC KEY that parses, so
private keys and corrupt files are refused. For other formats (e.g. SSH
keys), use --option with a path instead.

Later edits to <file> have no effect until it's added again. Adding an
existing <name> replaces it for every rule using it, which is how to
rotate a key.`

const trustKeyAddExample = `  # Store the team's cosign public key as "team"
  bomify trust key add team keys/team.pub

  # Rotate it: every rule using "team" now trusts the new key
  bomify trust key add team keys/team-2026.pub`

const trustKeyListShort = "List the public keys in the managed key store"

const trustKeyListLong = `List prints every stored key: its name, content hash, when it was
added, and the file it was copied from.`

const trustKeyListExample = `  # See every stored key
  bomify trust key list`

const trustKeyRemoveShort = "Remove a public key from the managed key store"

const trustKeyRemoveLong = `Remove deletes <name> from the key store, and its stored copy unless
another name shares it. It refuses while a "bomify trust" rule uses
<name>.`

const trustKeyRemoveExample = `  # Remove the key stored as "team"
  bomify trust key remove team`
