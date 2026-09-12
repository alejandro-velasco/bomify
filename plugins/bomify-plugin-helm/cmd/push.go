package cmd

import (
	"github.com/spf13/cobra"

	"bomify/plugins/bomify-plugin-helm/internal/chart"
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
		Short: "Push the chart a prior pull wrote into --input to an OCI registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := chart.Resolve(purl)
			if err != nil {
				return err
			}

			res, err := chart.Push(input, ref, remote)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the chart into (required)")
	cmd.Flags().StringVar(&remote, "remote", "", `OCI registry/repository to push to, e.g. "oci://registry.example.com/charts" (required)`)
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("remote")

	return cmd
}
