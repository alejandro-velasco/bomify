package plugin

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// NewRootCommand builds a plugin binary's root command,
// bomify-plugin-<kind>, with one subcommand per contract it implements
// (see ComponentCommand, SecurityCommand, SignatureCommand) — plus any
// that aren't parsed by bomify at all, like SBOM generation's (see
// plugins/SBOM-CONTRACT.md). Run executes it.
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
	return root
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
