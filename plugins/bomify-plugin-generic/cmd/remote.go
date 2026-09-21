package cmd

import (
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/internal/artifact"
)

// newRemoteCmd builds the `remote` subcommand.
func newRemoteCmd() *cobra.Command {
	var (
		purl     string
		logFile  string
		logColor bool
	)

	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Report the download URL this component's purl names",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, closeLog, err := plugin.OpenLog(logFile, logColor)
			if err != nil {
				return err
			}
			defer closeLog()

			ref, err := artifact.Resolve(purl)
			if err != nil {
				return err
			}
			logger.Info("resolved download URL", "download_url", ref.DownloadURL)

			res := plugin.RemoteResult{Remote: ref.DownloadURL}
			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
