// Package cmd contains the bomify CLI commands.
package cmd

import (
	"bomify/internal/logging"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

type rootOptions struct {
	verbose bool
	docsDir string
}

// NewRootCmd builds the bomify root command and wires up its subcommands.
func NewRootCmd() *cobra.Command {
	rootOpts := &rootOptions{}

	rootCmd := &cobra.Command{
		Use:           "bomify",
		Short:         "bomify builds packages from CycloneDX SBOMs",
		Long:          "bomify is a CLI that consumes a CycloneDX Software Bill of Materials (SBOM)\nand builds packages from the components it describes.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logger := logging.New(rootOpts.verbose)
			cmd.SetContext(logging.WithContext(cmd.Context(), logger))
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if rootOpts.docsDir != "" {
				if err := doc.GenMarkdownTree(cmd, rootOpts.docsDir); err != nil {
					return fmt.Errorf("generate docs: %w", err)
				}
			}
			return cmd.Help()
		},
	}

	// Disable the auto-generated tag in the documentation.
	rootCmd.DisableAutoGenTag = true

	rootCmd.PersistentFlags().BoolVar(&rootOpts.verbose, "verbose", false, "enable verbose (debug) logging")
	rootCmd.PersistentFlags().StringVar(&rootOpts.docsDir, "docs-dir", "", "directory to write documentation to (if empty, no docs are generated)")

	rootCmd.AddCommand(buildCmd())
	rootCmd.AddCommand(mirrorCmd())
	rootCmd.AddCommand(packagesCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}
