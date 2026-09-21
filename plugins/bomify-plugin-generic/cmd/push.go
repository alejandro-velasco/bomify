package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/internal/artifact"
)

// newPushCmd builds the `push` subcommand.
func newPushCmd() *cobra.Command {
	var (
		purl     string
		input    string
		remote   string
		check    bool
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

			if check {
				res, err := artifact.CheckPush(remote, logger)
				if err != nil {
					return err
				}
				return res.Print(cmd.OutOrStdout())
			}

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
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if !check && input == "" {
				return fmt.Errorf("required flag(s) \"input\" not set")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the artifact into (required unless --check)")
	cmd.Flags().StringVar(&remote, "remote", "", "destination URL to PUT the artifact to (required)")
	cmd.Flags().BoolVar(&check, "check", false, "best-effort verification that remote is reachable, without publishing anything")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("remote")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
