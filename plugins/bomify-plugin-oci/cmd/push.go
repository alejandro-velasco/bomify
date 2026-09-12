package cmd

import (
	"github.com/spf13/cobra"

	"bomify/plugins/bomify-plugin-oci/internal/image"
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
		Short: "Push the OCI Image Layout a prior pull wrote into --input to a remote endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := image.Push(input, purl, remote)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the OCI Image Layout into (required)")
	cmd.Flags().StringVar(&remote, "remote", "", "remote registry/repository to push to (required)")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("remote")

	return cmd
}
