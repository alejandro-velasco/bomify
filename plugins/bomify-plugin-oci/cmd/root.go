// Package cmd contains the bomify-plugin-oci CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the bomify-plugin-oci root command and wires up its
// pull/push subcommands.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "bomify-plugin-oci",
		Short:         "bomify plugin for container/OCI image components",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newPullCmd())
	rootCmd.AddCommand(newPushCmd())

	return rootCmd
}

// Execute runs the root command and returns any error encountered.
func Execute() error {
	return NewRootCmd().Execute()
}
