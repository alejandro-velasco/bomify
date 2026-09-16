package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/distribution"
)

func distributionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "distribution",
		Short: "Manage default remote endpoints for `bomify distribute`",
	}

	cmd.AddCommand(distributionCreateCmd())

	return cmd
}

func distributionCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <kind> <endpoint>",
		Short: "Create or update the default remote endpoint for a plugin kind",
		Long:  "Create sets <kind>'s default remote endpoint in <data-dir>/conf/distribution.json, the file `bomify distribute` falls back to for any kind not given a `--remote kind=endpoint`. Running it again for the same <kind> overwrites its endpoint.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := distribution.SetEndpoint(dataDir, args[0], args[1]); err != nil {
				return fmt.Errorf("distribution create: %w", err)
			}
			return nil
		},
	}

	return cmd
}
