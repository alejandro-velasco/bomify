package cmd

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-helm/internal/chart"
)

// newPullCmd builds the `pull` subcommand.
func newPullCmd() *cobra.Command {
	var (
		purl     string
		output   string
		hash     string
		logFile  string
		logColor bool
	)

	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Download the chart from its HTTP repository or OCI registry and save it as a .tgz",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, closeLog, err := plugin.OpenLog(logFile, logColor)
			if err != nil {
				return err
			}
			defer closeLog()

			logger.Info("resolving purl", "purl", purl)
			ref, err := chart.Resolve(purl)
			if err != nil {
				return err
			}
			logger.Info("resolved reference", "repository_url", ref.RepositoryURL, "oci", ref.OCI)

			res, err := chart.Pull(ref, output, cdx.HashAlgorithm(hash), logger)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&output, "output", "", "directory to save the pulled chart into (required)")
	cmd.Flags().StringVar(&hash, "hash", "", "hash algorithm to report the pulled chart's digest as")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("output")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
