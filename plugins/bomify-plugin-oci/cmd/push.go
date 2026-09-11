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
		remote        string
	)

	cmd := &cobra.Command{
		Use:   "push",
		Short: "Copy the component's image directly to a remote endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			component, err := plugin.DecodeComponent(componentJSON)
			if err != nil {
				return err
			}

			ref, err := image.Resolve(component)
			if err != nil {
				return err
			}

			res, err := image.Push(ref, component, remote)
			if err != nil {
				return err
			}

			return res.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&componentJSON, "component", "", "JSON-encoded CycloneDX component (required)")
	cmd.Flags().StringVar(&remote, "remote", "", "remote registry/repository to push to (required)")
	_ = cmd.MarkFlagRequired("component")
	_ = cmd.MarkFlagRequired("remote")

	return cmd
}
