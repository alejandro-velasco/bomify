package plugin

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// The major version of each plugin contract this package implements,
// which a plugin built with it reports through its "contract" subcommand
// (see NewRootCommand).
const (
	ComponentContractVersion = 1
	SBOMContractVersion      = 1
	SecurityContractVersion  = 1
	SigningContractVersion   = 1
)

// contractVersions maps each contract's top-level subcommand to the
// contract's name, as ContractResult reports it, and version.
var contractVersions = map[string]struct {
	name    string
	version int
}{
	"component": {"component", ComponentContractVersion},
	"sbom":      {"sbom", SBOMContractVersion},
	"security":  {"security", SecurityContractVersion},
	"signature": {"signing", SigningContractVersion},
}

// NewRootCommand builds a plugin binary's root command, bomify-plugin-<kind>,
// with one subcommand per contract it implements (see ComponentCommand,
// SecurityCommand, SignatureCommand) — plus any that aren't parsed by bomify
// at all, like SBOM generation's (see plugins/contracts/sbom/v1/CONTRACT.md).
// It adds a "contract" subcommand reporting each contract's version, by the
// name of its top-level subcommand. Run executes it.
func NewRootCommand(kind, short string, contracts ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{
		Use:   "bomify-plugin-" + kind,
		Short: short,
		// Errors are reported once, by Run, as the contract's single
		// stderr message; usage would only add noise there.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(contracts...)
	root.AddCommand(contractCommand(contracts))
	return root
}

// contractCommand builds the "contract" command, printing the
// ContractResult for the contracts' subcommands.
func contractCommand(contracts []*cobra.Command) *cobra.Command {
	result := ContractResult{Contracts: map[string]int{}}
	for _, cmd := range contracts {
		if c, ok := contractVersions[cmd.Name()]; ok {
			result.Contracts[c.name] = c.version
		}
	}
	return &cobra.Command{
		Use:   "contract",
		Short: "Print the plugin contracts this plugin implements and their versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return Print(cmd.OutOrStdout(), result)
		},
	}
}

// Run executes root and exits the way every plugin contract requires: 0
// on success, or non-zero with the error as one line on stderr, which
// bomify folds into its own error message.
func Run(root *cobra.Command) {
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// print is the RunE tail every contract's subcommand shares: print
// result as the command's one JSON result, or return err.
func print[T any](cmd *cobra.Command, result T, err error) error {
	if err != nil {
		return err
	}
	return Print(cmd.OutOrStdout(), result)
}
