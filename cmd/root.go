package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alejandro-velasco/bomify/internal/logging"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

const (
	// defaultDataDirEnv is the environment variable for specifying the default data directory for bomify.
	defaultDataDirEnv = "BOMIFY_DATA_DIR"
	// defaultDataDirName is the name of the default data directory for bomify.
	defaultDataDirName = ".bomify"
)

const rootShort = "bomify builds packages from CycloneDX SBOMs"

const rootLong = `bomify is a CLI that consumes a CycloneDX Software Bill of Materials
(SBOM) and builds packages from the components it describes.`

const rootExample = `  # Build a package from an SBOM, then publish it
  bomify build sbom.json --tag myapp:latest
  bomify push myapp:latest

  # See what's built locally
  bomify packages`

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
	defaultDataDir, err := defaultDataDir()
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
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logger := logging.New(rootOpts.verbose)
			cmd.SetContext(logging.WithContext(cmd.Context(), logger))

			if dataDir == "" {
				dataDir = defaultDataDir
			}
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
	rootCmd.AddCommand(pullCmd())
	rootCmd.AddCommand(pushCmd())
	rootCmd.AddCommand(rmpCmd())
	rootCmd.AddCommand(saveCmd())
	rootCmd.AddCommand(sbomCmd())
	rootCmd.AddCommand(tagCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd, nil
}

// defaultDataDir returns the default data directory for bomify, which is ~/.bomify.
// BOMIFY_DATA_DIR can be used to override this default.
func defaultDataDir() (string, error) {
	if envDir := os.Getenv(defaultDataDirEnv); envDir != "" {
		return envDir, nil
	}

	dir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get user home dir: %w", err)
	}
	return filepath.Join(dir, defaultDataDirName), nil
}
