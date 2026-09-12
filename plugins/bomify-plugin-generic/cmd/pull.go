package cmd

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"bomify/plugins/bomify-plugin-generic/internal/artifact"
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
		Short: "GET the artifact's download_url and save it",
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := artifact.Resolve(purl)
			if err != nil {
				return err
			}

			res, err := artifact.Pull(ref, output, cdx.HashAlgorithm(hash))
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	cmd.Flags().StringVar(&output, "output", "", "directory to save the pulled artifact into (required)")
	cmd.Flags().StringVar(&hash, "hash", "", "hash algorithm to report the pulled artifact's digest as")
	_ = cmd.MarkFlagRequired("purl")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}
