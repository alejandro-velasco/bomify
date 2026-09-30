package plugin

import (
	"context"

	"github.com/spf13/cobra"
)

// SecurityPlugin is a security scanning plugin's own logic (see
// plugins/SECURITY-CONTRACT.md), for SecurityCommand to expose as the
// contract's "security scan"/"security supported-components".
type SecurityPlugin interface {
	// Scan reports every vulnerability purl is affected by.
	Scan(ctx context.Context, purl string) (SecurityResult, error)
	// SupportedComponents reports which purl types and scan categories
	// Scan supports.
	SupportedComponents(ctx context.Context) (SupportedComponentsResult, error)
}

// SecurityHelp is the plugin-specific help text SecurityCommand shows.
type SecurityHelp struct {
	// Scan is "security scan"'s short description.
	Scan string
}

// SecurityCommand builds the "security" command implementing the
// security scanning plugin contract around p.
func SecurityCommand(p SecurityPlugin, help SecurityHelp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Security scanning subcommands — see plugins/SECURITY-CONTRACT.md",
	}

	var purl string
	scan := &cobra.Command{
		Use:   "scan",
		Short: help.Scan,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := p.Scan(cmd.Context(), purl)
			return print(cmd, result, err)
		},
	}
	scan.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	_ = scan.MarkFlagRequired("purl")

	supported := &cobra.Command{
		Use:   "supported-components",
		Short: "Report the purl types and scan categories this plugin supports",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := p.SupportedComponents(cmd.Context())
			return print(cmd, result, err)
		},
	}

	cmd.AddCommand(scan, supported)
	return cmd
}
