// Package cmd contains the bomify CLI commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X bomify/cmd.version=x.y.z".
var version = "dev"

var verbose bool

var rootCmd = &cobra.Command{
	Use:           "bomify",
	Short:         "bomify builds packages from CycloneDX SBOMs",
	Long:          "bomify is a CLI that consumes a CycloneDX Software Bill of Materials (SBOM)\nand builds packages from the components it describes.",
	Version:       version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command and returns any error encountered.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}
