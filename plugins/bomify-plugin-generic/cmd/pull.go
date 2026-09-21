package cmd

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/internal/artifact"
)

// newPullCmd builds the `pull` subcommand.
func newPullCmd() *cobra.Command {
	var (
		purl     string
		output   string
		hash     string
		check    bool
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

			if check {
				res, err := artifact.CheckPull(ref, logger)
				if err != nil {
					return err
				}
				return res.Print(cmd.OutOrStdout())
			}

			res, err := artifact.Pull(ref, output, cdx.HashAlgorithm(hash), logger)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if !check && output == "" {
				return fmt.Errorf("required flag(s) \"output\" not set")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&output, "output", "", "directory to save the pulled artifact into (required unless --check)")
	cmd.Flags().StringVar(&hash, "hash", "", "hash algorithm to report the pulled artifact's digest as")
	cmd.Flags().BoolVar(&check, "check", false, "verify the artifact exists and is pullable without downloading it")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
