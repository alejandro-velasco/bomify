package plugin

import (
	"context"

	"github.com/spf13/cobra"
)

// SecurityPlugin is a security scanning plugin's own logic (see
// plugins/contracts/security/v1/CONTRACT.md), for SecurityCommand to expose
// as the contract's "security scan"/"security supported-components".
type SecurityPlugin interface {
	// Scan reports every vulnerability purl is affected by.
	Scan(ctx context.Context, purl string) (SecurityResult, error)
	// SupportedComponents reports which purl types and scan categories
	// Scan supports.
	SupportedComponents(ctx context.Context) (SupportedComponentsResult, error)
}

// InputScanner is a SecurityPlugin that can also analyze a component's
// pulled files, for the types it scans ByFiles (see ScanMode).
// SecurityCommand calls ScanInput instead of Scan when bomify passes
// "security scan --input"; a plugin that doesn't implement it is only
// ever asked to Scan, and the files are ignored.
type InputScanner interface {
	// ScanInput reports every vulnerability purl is affected by, from its
	// files in the directory input as well as its purl.
	ScanInput(ctx context.Context, purl, input string) (SecurityResult, error)
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
		Use:   SecuritySubcommand,
		Short: "Security scanning subcommands — see plugins/contracts/security/v1/CONTRACT.md",
	}

	var purl, input string
	scan := &cobra.Command{
		Use:   "scan",
		Short: help.Scan,
		RunE: func(cmd *cobra.Command, args []string) error {
			if is, ok := p.(InputScanner); ok && input != "" {
				result, err := is.ScanInput(cmd.Context(), purl, input)
				return print(cmd, result, err)
			}
			result, err := p.Scan(cmd.Context(), purl)
			return print(cmd, result, err)
		},
	}
	scan.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	_ = scan.MarkFlagRequired("purl")
	scan.Flags().StringVar(&input, "input", "", "directory holding the component's pulled files, when bomify has them")

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
