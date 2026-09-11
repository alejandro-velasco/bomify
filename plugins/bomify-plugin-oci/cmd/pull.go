package cmd

import (
	"github.com/spf13/cobra"

	"bomify/internal/plugin"
	"bomify/plugins/bomify-plugin-oci/internal/image"
)

// newPullCmd builds the `pull` subcommand.
func newPullCmd() *cobra.Command {
	var (
		componentJSON string
		output        string
	)

	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Download the component's image and save it as a tarball",
		RunE: func(cmd *cobra.Command, args []string) error {
			component, err := plugin.DecodeComponent(componentJSON)
			if err != nil {
				return err
			}

			ref, err := image.Resolve(component)
			if err != nil {
				return err
			}

			res, err := image.Pull(ref, component, output)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&componentJSON, "component", "", "JSON-encoded CycloneDX component (required)")
	cmd.Flags().StringVar(&output, "output", "", "directory to save the pulled image into (required)")
	_ = cmd.MarkFlagRequired("component")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}
