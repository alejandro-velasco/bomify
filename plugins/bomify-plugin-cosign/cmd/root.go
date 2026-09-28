// Package cmd contains the bomify-plugin-cosign CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the bomify-plugin-cosign root command and wires up
// its signature sign/verify/supported-types subcommands (see
// plugins/SIGNING-CONTRACT.md).
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "bomify-plugin-cosign",
		Short:         "bomify signing plugin producing Sigstore bundles, cosign-style",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(signatureCmd())

	return rootCmd
}

// Execute runs the root command and returns any error encountered.
func Execute() error {
	return NewRootCmd().Execute()
}
