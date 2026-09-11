package cmd

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/internal/artifact"
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
		Short: "GET the artifact's download_url and save it",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, closeLog, err := plugin.OpenLog(logFile, logColor)
			if err != nil {
				return err
			}
			defer closeLog()

			logger.Info("resolving purl", "purl", purl)
			ref, err := artifact.Resolve(purl)
			if err != nil {
				return err
			}
			logger.Info("resolved reference", "download_url", ref.DownloadURL)

			res, err := artifact.Pull(ref, output, cdx.HashAlgorithm(hash), logger)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&output, "output", "", "directory to save the pulled artifact into (required)")
	cmd.Flags().StringVar(&hash, "hash", "", "hash algorithm to report the pulled artifact's digest as")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("output")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
