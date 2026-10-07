package cmd

import (
	"fmt"
	"os"
	"slices"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const rootShort = "bomify builds packages from CycloneDX SBOMs"

const rootLong = `bomify is a CLI that consumes a CycloneDX Software Bill of Materials
(SBOM) and builds packages from the components it describes.`

const rootExample = `  # Build a package from an SBOM, then publish it
  bomify build sbom.json --tag myapp:latest
  bomify push myapp:latest

  # See what's built locally
  bomify packages`

// commandsWithoutDataDir are the top-level commands that never read or
// write the data directory, so don't check its version (see usesDataDir).
// help and completion are cobra's own.
var commandsWithoutDataDir = []string{"completion", "help", "version"}

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
	defaultDataDir, err := layout.DefaultDataDir()
	if err != nil {
		return nil, fmt.Errorf("determine default data dir: %w", err)
	}

	rootOpts := &rootOptions{}
	rootCmd := &cobra.Command{
		Use:           "bomify",
		Short:         rootShort,
		Long:          rootLong,
		Example:       rootExample,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.New(rootOpts.verbose)
			cmd.SetContext(logging.WithContext(cmd.Context(), logger))

			if dataDir == "" {
				dataDir = defaultDataDir
			}
			// internal/auth and plugins (through pkg/auth) find
			// conf/auth.json from this.
			if err := os.Setenv(layout.DataDirEnv, dataDir); err != nil {
				return fmt.Errorf("set %s: %w", layout.DataDirEnv, err)
			}
			if !usesDataDir(cmd) {
				return nil
			}
			return layout.CheckVersion(dataDir)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if rootOpts.docsDir != "" {
				cmd.DisableAutoGenTag = true

				if err := doc.GenMarkdownTree(cmd, rootOpts.docsDir); err != nil {
					return fmt.Errorf("generate docs: %w", err)
				}

				return nil
			}

			return cmd.Help()
		},
	}

	rootCmd.PersistentFlags().BoolVar(&rootOpts.verbose, "verbose", false, "enable verbose (debug) logging")
	rootCmd.PersistentFlags().StringVar(&rootOpts.docsDir, "docs-dir", "", "directory to write documentation to (if empty, no docs are generated)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "directory to store bomify data (e.g., built packages). default is $HOME/.bomify or the value of the BOMIFY_DATA_DIR environment variable")

	rootCmd.AddCommand(buildCmd())
	rootCmd.AddCommand(distributeCmd())
	rootCmd.AddCommand(distributionCmd())
	rootCmd.AddCommand(loadCmd())
	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(logoutCmd())
	rootCmd.AddCommand(packageCmd())
	rootCmd.AddCommand(packagesCmd())
	rootCmd.AddCommand(pluginCmd())
	rootCmd.AddCommand(pullCmd())
	rootCmd.AddCommand(pushCmd())
	rootCmd.AddCommand(rmpCmd())
	rootCmd.AddCommand(saveCmd())
	rootCmd.AddCommand(sbomCmd())
	rootCmd.AddCommand(securityCmd())
	rootCmd.AddCommand(signCmd())
	rootCmd.AddCommand(signerCmd())
	rootCmd.AddCommand(tagCmd())
	rootCmd.AddCommand(trustCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd, nil
}

// usesDataDir reports whether cmd reads or writes the data directory: the
// root command itself only prints help or generates docs.
func usesDataDir(cmd *cobra.Command) bool {
	if !cmd.HasParent() {
		return false
	}
	topLevel := cmd
	for topLevel.Parent().HasParent() {
		topLevel = topLevel.Parent()
	}
	return !slices.Contains(commandsWithoutDataDir, topLevel.Name())
}
