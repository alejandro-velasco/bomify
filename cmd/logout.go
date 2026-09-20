package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/auth"
)

const logoutShort = "Log out from an OCI registry"

const logoutLong = `Logout removes stored credentials for an OCI registry (default:
docker.io).`

const logoutExample = `  # Log out from docker.io
  bomify logout

  # Log out from a specific registry
  bomify logout registry.example.com`

func logoutCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "logout [server]",
		Short:   logoutShort,
		Long:    logoutLong,
		Example: logoutExample,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := auth.DefaultHost
			if len(args) == 1 {
				host = args[0]
			}
			if err := auth.Logout(cmd.Context(), host); err != nil {
				return fmt.Errorf("logout: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed login credentials for %s\n", host)
			return nil
		},
	}

	return cmd
}
