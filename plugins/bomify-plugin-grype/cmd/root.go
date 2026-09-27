// Package cmd contains the bomify-plugin-grype CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the bomify-plugin-grype root command and wires up
// its security scan/supported-components subcommands (see
// plugins/SECURITY-CONTRACT.md).
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "bomify-plugin-grype",
		Short:         "bomify security scanning plugin backed by grype",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(securityCmd())

	return rootCmd
}

// Execute runs the root command and returns any error encountered.
func Execute() error {
	return NewRootCmd().Execute()
}
