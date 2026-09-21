package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-oci/internal/image"
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
		Short: "Push the OCI Image Layout a prior pull wrote into --input to a remote endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, closeLog, err := plugin.OpenLog(logFile, logColor)
			if err != nil {
				return err
			}
			defer closeLog()

			if check {
				res, err := image.CheckPush(purl, remote, logger)
				if err != nil {
					return err
				}
				return res.Print(cmd.OutOrStdout())
			}

			res, err := image.Push(input, purl, remote, logger)
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
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the OCI Image Layout into (required unless --check)")
	cmd.Flags().StringVar(&remote, "remote", "", "remote registry/repository to push to (required)")
	cmd.Flags().BoolVar(&check, "check", false, "verify push permission to remote without publishing anything")
	cmd.Flags().StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	cmd.Flags().BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("remote")
	_ = cmd.MarkFlagRequired("log")

	return cmd
}
