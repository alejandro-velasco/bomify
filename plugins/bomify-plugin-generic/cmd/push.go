package cmd

import (
	"github.com/spf13/cobra"

	"bomify/plugins/bomify-plugin-generic/internal/artifact"
)

// newPushCmd builds the `push` subcommand.
func newPushCmd() *cobra.Command {
	var (
		purl   string
		input  string
		remote string
	)

	cmd := &cobra.Command{
		Use:   "push",
		Short: "PUT the artifact a prior pull wrote into --input to --remote",
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := artifact.Resolve(purl)
			if err != nil {
				return err
			}

			res, err := artifact.Push(input, ref, remote)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the artifact into (required)")
	cmd.Flags().StringVar(&remote, "remote", "", "destination URL to PUT the artifact to (required)")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("remote")

	return cmd
}
