// Package cmd contains the bomify-plugin-generic CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the bomify-plugin-generic root command and wires up
// its pull/push/remote subcommands.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "bomify-plugin-generic",
		Short:         "bomify plugin for plain HTTP GET/PUT artifacts",
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
