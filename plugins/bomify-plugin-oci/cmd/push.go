package cmd

import (
	"github.com/spf13/cobra"

	"bomify/internal/plugin"
	"bomify/plugins/bomify-plugin-oci/internal/image"
)

// newPushCmd builds the `push` subcommand.
func newPushCmd() *cobra.Command {
	var (
		componentJSON string
		input         string
		remote        string
	)

	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push the OCI Image Layout a prior pull wrote into --input to a remote endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			component, err := plugin.DecodeComponent(componentJSON)
			if err != nil {
				return err
			}

			res, err := image.Push(input, component, remote)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&componentJSON, "component", "", "JSON-encoded CycloneDX component (required)")
	cmd.Flags().StringVar(&input, "input", "", "directory a prior pull wrote the OCI Image Layout into (required)")
	cmd.Flags().StringVar(&remote, "remote", "", "remote registry/repository to push to (required)")
	_ = cmd.MarkFlagRequired("component")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("remote")

	return cmd
}
