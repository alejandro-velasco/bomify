package cmd

import (
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-oci/internal/image"
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
		Short: "Report the registry/namespace this component's purl names",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, closeLog, err := plugin.OpenLog(logFile, logColor)
			if err != nil {
				return err
			}
			defer closeLog()

			location, err := image.Location(purl)
			if err != nil {
				return err
			}
			logger.Info("resolved location", "location", location)

			res := plugin.RemoteResult{Remote: location}
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
