package cmd

import (
	"fmt"
	"sort"
	"strconv"
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

const trustCreateLong = `Create adds a signer to the rule for --match (a "/"-separated prefix
of a package's repository; omit it to match every package), creating the
rule if needed. "bomify pull" and "bomify load" restore a matching
package only if, for each of the rule's signers, one of its signatures
verifies with bomify-plugin-<plugin>. The longest matching --match
wins.

--signer names the signer to add, or to replace if the rule already has
one by that name. Without it, the signer is unnamed ("-" in "bomify
trust list"), so repeating a plain "trust create" replaces the rule's
one signer. Add signers under different names to require several
signatures, e.g. from a release team and a security team, and --require
<k> to accept any k of them instead of all.

An unnamed signer stays when named ones are added: a rule first created
without --signer and then given "--signer security" requires both.
Remove it with "bomify trust remove --signer ''", or create the rule
with names from the start.

--option (key=value) is passed to the plugin's verify unparsed, e.g. the
key or identity to trust. --key-option (option=name) instead names a key
from "bomify trust key add"; the plugin receives the stored copy's path
as that option. The same option can't be given both ways.

--require-provenance also requires the package's build provenance (see
"bomify build --provenance"), attested by someone one of the rule's
signers trusts. --require and --require-provenance apply to the whole
rule, and change only when given.

"--verify" on pull or load overrides every rule, and
"--insecure-skip-verify" bypasses them.`

const trustCreateExample = `  # Require packages from a team's repositories to be signed with its cosign key
  bomify trust create sigstore --match registry.example.com/team --option key=team.pub

  # Require every package to be signed with the organization's key
  bomify trust create sigstore --option key=org.pub

  # The same, with the key kept in the managed key store
  bomify trust key add org org.pub
  bomify trust create sigstore --key-option key=org

  # Also require build provenance attested with that key
  bomify trust create sigstore --key-option key=org --require-provenance

  # Require signatures from both the release and security teams
  bomify trust create sigstore --match registry.example.com/prod --signer release --key-option key=release
  bomify trust create sigstore --match registry.example.com/prod --signer security --key-option key=security

  # Accept any two of three maintainers
  bomify trust create sigstore --match registry.example.com/oss --signer alice --key-option key=alice
  bomify trust create sigstore --match registry.example.com/oss --signer bob --key-option key=bob
  bomify trust create sigstore --match registry.example.com/oss --signer carol --key-option key=carol --require 2`

type trustCreateOptions struct {
	match      string
	signer     string
	options    []string
	keyOptions []string
	require    string
	provenance bool
}

func trustCreateCmd() *cobra.Command {
	opts := &trustCreateOptions{}

	cmd := &cobra.Command{
		Use:     "create <plugin>",
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
			require, err := parseRequire(opts.require)
			if err != nil {
				return fmt.Errorf("trust create: %w", err)
			}
			signer := signature.Signer{Name: opts.signer, Kind: args[0], Options: opts.options, KeyOptions: keyOptions}
			err = signature.UpdateRule(dataDir, opts.match, func(rule *signature.Rule) {
				rule.SetSigner(signer)
				if cmd.Flags().Changed("require") {
					rule.Require = require
				}
				if cmd.Flags().Changed("require-provenance") {
					rule.Provenance = opts.provenance
				}
			})
			if err != nil {
				return fmt.Errorf("trust create: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.match, "match", "", "apply to packages whose repository starts with this \"/\"-separated prefix; default applies to every package")
	cmd.Flags().StringVar(&opts.signer, "signer", "", "the name of the rule's signer to add or replace; default is the rule's unnamed signer")
	cmd.Flags().StringArrayVar(&opts.options, "option", nil, "a key=value option passed through to the plugin (repeatable)")
	cmd.Flags().StringArrayVar(&opts.keyOptions, "key-option", nil, "an option=name pair: pass the plugin option=<path of the stored key name> (see \"bomify trust key add\"; repeatable)")
	cmd.Flags().StringVar(&opts.require, "require", "all", "how many of the rule's signers must verify: \"all\", or a number")
	cmd.Flags().BoolVar(&opts.provenance, "require-provenance", false, "also require the package's build provenance, attested by someone one of the rule's signers trusts")

	return cmd
}

// parseRequire parses --require: "all" is 0, as signature.Rule stores
// it, and anything else a positive number.
func parseRequire(s string) (int, error) {
	if s == "all" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("--require %s: must be \"all\" or a number of at least 1", s)
	}
	return n, nil
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

const trustListLong = `List prints every trust rule, one row per signer. "*" in MATCH means
every package, KEY-OPTIONS lists each option=name pair naming a stored
key, and REQUIRE is how many of the rule's signers must verify. "-"
marks an empty field; in SIGNER, it's the rule's unnamed signer.`

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

	var rows [][]string
	for _, rule := range config {
		for _, signer := range rule.Signers {
			row := []string{
				rules.Display(rule.Match),
				dashIfEmpty(signer.Name),
				signer.Kind,
				dashIfEmpty(strings.Join(signer.Options, ",")),
				dashIfEmpty(formatKeyOptions(signer.KeyOptions)),
				formatRequire(rule),
				formatProvenance(rule.Provenance),
			}
			rows = append(rows, row)
		}
	}
	return table.Write(cmd.OutOrStdout(), []string{"MATCH", "SIGNER", "PLUGIN", "OPTIONS", "KEY-OPTIONS", "REQUIRE", "PROVENANCE"}, rows)
}

// formatRequire renders how many of rule's signers must verify: "all",
// or "k of n".
func formatRequire(rule signature.Rule) string {
	if rule.Require == 0 {
		return "all"
	}
	return fmt.Sprintf("%d of %d", rule.Require, len(rule.Signers))
}

const trustRemoveShort = "Remove a signature verification rule"

const trustRemoveLong = `Remove drops the rule matching --match exactly (as "bomify trust
list" prints it) from <data-dir>/conf/trust.json, or with --signer just
that signer, and the rule along with its last one. --signer '' removes
the rule's unnamed signer ("-" in "bomify trust list").

After --signer removes one, a rule with "--require all" requires every
signer left. A rule with a number refuses to drop below it: removing a
signer from a rule requiring 2 of 2 fails until its --require is
lowered.`

const trustRemoveExample = `  # Remove the rule for a team's repositories
  bomify trust remove --match registry.example.com/team

  # Remove the rule applying to every package (no --match)
  bomify trust remove

  # Stop requiring the security team's signature
  bomify trust remove --match registry.example.com/prod --signer security

  # Drop the unnamed signer a rule kept after named ones were added
  bomify trust remove --match registry.example.com/prod --signer ''`

func trustRemoveCmd() *cobra.Command {
	var match, signer string

	cmd := &cobra.Command{
		Use:     "remove",
		Short:   trustRemoveShort,
		Long:    trustRemoveLong,
		Example: trustRemoveExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if cmd.Flags().Changed("signer") {
				err = signature.RemoveSigner(dataDir, match, signer)
			} else {
				err = signature.RemoveRule(dataDir, match)
			}
			if err != nil {
				return fmt.Errorf("trust remove: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&match, "match", "", "the rule's match prefix, exactly as \"bomify trust list\" prints it (empty for a rule with no --match)")
	cmd.Flags().StringVar(&signer, "signer", "", "remove only this signer from the rule ('' for its unnamed signer)")

	return cmd
}

// formatProvenance renders whether a rule requires provenance.
func formatProvenance(required bool) string {
	if required {
		return "required"
	}
	return "-"
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
