package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/alejandro-velasco/bomify/internal/buildinfo"

	"github.com/spf13/cobra"
)

const versionShort = "Print version, commit, and build date information"

const versionExample = `  # Print human-readable version info
  bomify version

  # Print version info as JSON
  bomify version --output json`

type VersionOptions struct {
	Output string
}

func versionCmd() *cobra.Command {
	versionOpts := &VersionOptions{}

	cmd := &cobra.Command{
		Use:     "version",
		Short:   versionShort,
		Example: versionExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			buildInfo := buildinfo.GetBuildInfo()

			switch versionOpts.Output {
			case "text":
				fmt.Fprintf(cmd.OutOrStdout(), "version: %s\n", buildInfo.Version)
				fmt.Fprintf(cmd.OutOrStdout(), "commit:  %s\n", buildInfo.Commit)
				fmt.Fprintf(cmd.OutOrStdout(), "built:   %s\n", buildInfo.Date)
				fmt.Fprintf(cmd.OutOrStdout(), "go:      %s\n", buildInfo.GoVersion)
			case "json":
				buildInfoJSON, err := json.Marshal(buildInfo)
				if err != nil {
					return fmt.Errorf("marshal build info: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(buildInfoJSON))
			default:
				return fmt.Errorf("invalid output format: %q", versionOpts.Output)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&versionOpts.Output, "output", "o", "text", "output format (text or json)")

	return cmd
}
