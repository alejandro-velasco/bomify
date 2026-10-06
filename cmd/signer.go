package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/signature"
	"github.com/alejandro-velasco/bomify/internal/table"
)

const signerShort = "Manage named signers for bomify push and save"

func signerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signer",
		Short: signerShort,
	}

	cmd.AddCommand(signerCreateCmd())
	cmd.AddCommand(signerListCmd())
	cmd.AddCommand(signerRemoveCmd())

	return cmd
}

const signerCreateShort = "Create or update a named signer"

const signerCreateLong = `Create stores <name> as a way to sign: bomify-plugin-<plugin> with
--option (key=value) passed to its sign unparsed, e.g. the key to sign
with. "bomify push" and "bomify save" sign as it with --signer <name>,
and repeating --signer signs as several signers at once, for a trust
rule requiring more than one. Creating an existing <name> replaces it.

Only options are stored, such as a private key's path, never key
material.`

const signerCreateExample = `  # Sign as "release" with a cosign key
  bomify signer create release sigstore --option key=release.key

  # A second signer, for a rule requiring both
  bomify signer create security sigstore --option key=security.key

  # Sign a package as both while pushing it
  bomify push registry.example.com/myapp:1.0 --signer release --signer security`

func signerCreateCmd() *cobra.Command {
	var options []string

	cmd := &cobra.Command{
		Use:     "create <name> <plugin>",
		Short:   signerCreateShort,
		Long:    signerCreateLong,
		Example: signerCreateExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateOptions("--option", options); err != nil {
				return fmt.Errorf("signer create: %w", err)
			}
			profile := signature.Profile{
				Name:    args[0],
				Kind:    args[1],
				Options: options,
			}
			if err := signature.SetProfile(dataDir, profile); err != nil {
				return fmt.Errorf("signer create: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&options, "option", nil, "a key=value option passed through to the signing plugin (repeatable)")

	return cmd
}

const signerListShort = "List named signers"

const signerListLong = `List prints every stored signer: its name, signing plugin, and options.`

const signerListExample = `  # See every stored signer
  bomify signer list`

func signerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   signerListShort,
		Long:    signerListLong,
		Example: signerListExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := signature.ReadProfiles(dataDir)
			if err != nil {
				return err
			}
			sort.SliceStable(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

			rows := make([][]string, 0, len(profiles))
			for _, p := range profiles {
				rows = append(rows, []string{p.Name, p.Kind, strings.Join(p.Options, ",")})
			}
			return table.Write(cmd.OutOrStdout(), []string{"NAME", "PLUGIN", "OPTIONS"}, rows)
		},
	}
}

const signerRemoveShort = "Remove a named signer"

const signerRemoveLong = `Remove deletes <name> from the stored signers. Signatures it already
made are unaffected.`

const signerRemoveExample = `  # Remove the "security" signer
  bomify signer remove security`

func signerRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Short:   signerRemoveShort,
		Long:    signerRemoveLong,
		Example: signerRemoveExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := signature.RemoveProfile(dataDir, args[0]); err != nil {
				return fmt.Errorf("signer remove: %w", err)
			}
			return nil
		},
	}
}
