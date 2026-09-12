package cmd

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"bomify/plugins/bomify-plugin-helm/internal/chart"
)

// newPullCmd builds the `pull` subcommand.
func newPullCmd() *cobra.Command {
	var (
		purl   string
		output string
		hash   string
	)

	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Download the chart from its HTTP repository or OCI registry and save it as a .tgz",
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := chart.Resolve(purl)
			if err != nil {
				return err
			}

			res, err := chart.Pull(ref, output, cdx.HashAlgorithm(hash))
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&output, "output", "", "directory to save the pulled chart into (required)")
	cmd.Flags().StringVar(&hash, "hash", "", "hash algorithm to report the pulled chart's digest as")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}
