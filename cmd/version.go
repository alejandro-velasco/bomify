package cmd

import (
	"fmt"
	"io"

	"github.com/alejandro-velasco/bomify/internal/buildinfo"

	"github.com/spf13/cobra"
)

const versionShort = "Print version, commit, and build date information"

const versionExample = `  # Print human-readable version info
  bomify version

  # Print version info as JSON
  bomify version --format json`

type versionOptions struct {
	format formatType
}

func versionCmd() *cobra.Command {
	opts := &versionOptions{}

	cmd := &cobra.Command{
		Use:     "version",
		Short:   versionShort,
		Example: versionExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeVersion(cmd.OutOrStdout(), opts.format)
		},
	}

	registerFormat(cmd, &opts.format)
	// --output was --format's name before every command shared it.
	cmd.Flags().VarP(&opts.format, "output", "o", formatUsage)
	cmd.Flags().MarkDeprecated("output", "use --format")

	return cmd
}

// writeVersion prints bomify's build information in format.
func writeVersion(w io.Writer, format formatType) error {
	buildInfo := buildinfo.GetBuildInfo()
	if format == formatTypeJSON {
		return writeJSON(w, buildInfo)
	}
	fmt.Fprintf(w, "version: %s\n", buildInfo.Version)
	fmt.Fprintf(w, "commit:  %s\n", buildInfo.Commit)
	fmt.Fprintf(w, "built:   %s\n", buildInfo.Date)
	fmt.Fprintf(w, "go:      %s\n", buildInfo.GoVersion)
	return nil
}
