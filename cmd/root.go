// Package cmd contains the bomify CLI commands.
package cmd

import (
	"bomify/internal/logging"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var (
	// DataDir is the directory where bomify stores its data (e.g., built packages).
	// It is set by the main package.
	dataDir string
)

type rootOptions struct {
	verbose bool
	docsDir string
}

// NewRootCmd builds the bomify root command and wires up its subcommands.
func NewRootCmd() (*cobra.Command, error) {
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

	defaultDataDir, err := defaultDataDir()
	if err != nil {
		return nil, fmt.Errorf("determine default data dir: %w", err)
	}

	// Disable the auto-generated tag in the documentation.
	rootCmd.DisableAutoGenTag = true

	rootCmd.PersistentFlags().BoolVar(&rootOpts.verbose, "verbose", false, "enable verbose (debug) logging")
	rootCmd.PersistentFlags().StringVar(&rootOpts.docsDir, "docs-dir", "", "directory to write documentation to (if empty, no docs are generated)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", defaultDataDir, "directory to store bomify data (e.g., built packages)")

	rootCmd.AddCommand(buildCmd())
	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(logoutCmd())
	rootCmd.AddCommand(mirrorCmd())
	rootCmd.AddCommand(packageCmd())
	rootCmd.AddCommand(packagesCmd())
	rootCmd.AddCommand(pullCmd())
	rootCmd.AddCommand(pushCmd())
	rootCmd.AddCommand(rmpCmd())
	rootCmd.AddCommand(tagCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd, nil
}

// defaultDataDir returns the default data directory for bomify, which is ~/.bomify.
func defaultDataDir() (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get user home dir: %w", err)
	}
	return filepath.Join(dir, ".bomify"), nil
}
