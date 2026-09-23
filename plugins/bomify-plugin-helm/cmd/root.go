// Package cmd contains the bomify-plugin-helm CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the bomify-plugin-helm root command and wires up its
// component pull/push/remote subcommands.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "bomify-plugin-helm",
		Short:         "bomify plugin for Helm chart components",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(componentCmd())

	return rootCmd
}

// componentCmd groups the component plugin contract's pull/push/remote
// subcommands (see plugins/CONTRACT.md), kept independent of any other
// plugin class (e.g. sbom generate) this binary might also implement.
func componentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component",
		Short: "Component plugin subcommands (pull/push/remote) — see plugins/CONTRACT.md",
	}

	cmd.AddCommand(newPullCmd())
	cmd.AddCommand(newPushCmd())
	cmd.AddCommand(newRemoteCmd())

	return cmd
}

// Execute runs the root command and returns any error encountered.
func Execute() error {
	return NewRootCmd().Execute()
}
