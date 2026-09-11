package cmd

import (
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/internal/artifact"
)

// newPushCmd builds the `push` subcommand.
func newPushCmd() *cobra.Command {
	var (
		purl     string
		input    string
		remote   string
		logFile  string
		logColor bool
	)

	cmd := &cobra.Command{
		Use:   "push",
		Short: "PUT the artifact a prior pull wrote into --input to --remote",
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

			res, err := artifact.Push(input, ref, remote, logger)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the artifact into (required)")
	cmd.Flags().StringVar(&remote, "remote", "", "destination URL to PUT the artifact to (required)")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("remote")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
