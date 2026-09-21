package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-helm/internal/chart"
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
		Short: "Push the chart a prior pull wrote into --input to an OCI registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, closeLog, err := plugin.OpenLog(logFile, logColor)
			if err != nil {
				return err
			}
			defer closeLog()

			ref, err := chart.Resolve(purl)
			if err != nil {
				return err
			}

			if check {
				res, err := chart.CheckPush(ref, remote, logger)
				if err != nil {
					return err
				}
				return res.Print(cmd.OutOrStdout())
			}

			res, err := chart.Push(input, ref, remote, logger)
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
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the chart into (required unless --check)")
	cmd.Flags().StringVar(&remote, "remote", "", `OCI registry/repository to push to, e.g. "oci://registry.example.com/charts" (required)`)
	cmd.Flags().BoolVar(&check, "check", false, "verify push permission to remote without publishing anything")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("remote")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
