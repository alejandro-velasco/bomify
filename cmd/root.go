// Package cmd contains the bomify CLI commands.
package cmd

import (
	"github.com/spf13/cobra"

	"bomify/internal/logging"
)

// NewRootCmd builds the bomify root command and wires up its subcommands.
func NewRootCmd() *cobra.Command {
	var verbose bool

	rootCmd := &cobra.Command{
		Use:           "bomify",
		Short:         "bomify builds packages from CycloneDX SBOMs",
		Long:          "bomify is a CLI that consumes a CycloneDX Software Bill of Materials (SBOM)\nand builds packages from the components it describes.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logger := logging.New(verbose)
			cmd.SetContext(logging.WithContext(cmd.Context(), logger))
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose (debug) logging")

	rootCmd.AddCommand(packageCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}
