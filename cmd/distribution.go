package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/distribution"
)

const distributionShort = "Manage default remote endpoints for bomify distribute"

func distributionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "distribution",
		Short: distributionShort,
	}

	cmd.AddCommand(distributionCreateCmd())

	return cmd
}

const distributionCreateShort = "Create or update the default remote endpoint for a plugin kind"

const distributionCreateLong = `Create sets <kind>'s default remote endpoint in
<data-dir>/conf/distribution.json, the file "bomify distribute" falls
back to for any kind not given a --remote kind=endpoint. Running it
again for the same <kind> overwrites its endpoint.`

const distributionCreateExample = `  # Fall back to this OCI registry whenever --remote oci=... isn't given
  bomify distribution create oci registry.example.com

  # Do the same for the helm plugin kind
  bomify distribution create helm charts.example.com/helm`

func distributionCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create <kind> <endpoint>",
		Short:   distributionCreateShort,
		Long:    distributionCreateLong,
		Example: distributionCreateExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := distribution.SetEndpoint(dataDir, args[0], args[1]); err != nil {
				return fmt.Errorf("distribution create: %w", err)
			}
			return nil
		},
	}

	return cmd
}
