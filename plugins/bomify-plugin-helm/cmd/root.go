// Package cmd contains the bomify-plugin-helm CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the bomify-plugin-helm root command and wires up its
// pull/push/remote subcommands.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "bomify-plugin-helm",
		Short:         "bomify plugin for Helm chart components",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newPullCmd())
	rootCmd.AddCommand(newPushCmd())
	rootCmd.AddCommand(newRemoteCmd())

	return rootCmd
}

// Execute runs the root command and returns any error encountered.
func Execute() error {
	return NewRootCmd().Execute()
}
