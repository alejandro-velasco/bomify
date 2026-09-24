package cmd

import (
	"github.com/spf13/cobra"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-grype/internal/scan"
)

// securityCmd groups the security scanning plugin contract's
// subcommands (see plugins/SECURITY-CONTRACT.md), kept independent of
// any other plugin class this binary might also implement.
func securityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Security scanning subcommands — see plugins/SECURITY-CONTRACT.md",
	}

	cmd.AddCommand(newSecurityScanCmd())
	cmd.AddCommand(newSecuritySupportedComponentsCmd())

	return cmd
}

// newSecurityScanCmd builds the `security scan` subcommand.
func newSecurityScanCmd() *cobra.Command {
	var purl string

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Report the vulnerabilities the given purl is affected by, via grype's vulnerability database",
		RunE: func(cmd *cobra.Command, args []string) error {
			provider, err := scan.Load()
			if err != nil {
				return err
			}
			defer provider.Close()

			vulnerabilities, err := scan.Purl(provider, purl)
			if err != nil {
				return err
			}

			result := pluginlib.SecurityResult(vulnerabilities)
			return result.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&purl, "purl", "", "component purl (required)")
	_ = cmd.MarkFlagRequired("purl")

	return cmd
}

// newSecuritySupportedComponentsCmd builds the `security
// supported-components` subcommand.
func newSecuritySupportedComponentsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "supported-components",
		Short: "Report the purl types and scan categories this plugin supports",
		RunE: func(cmd *cobra.Command, args []string) error {
			result := pluginlib.SupportedComponentsResult{
				Types: scan.SupportedTypes(),
				Scans: []string{"sca"},
			}
			return result.Print(cmd.OutOrStdout())
		},
	}
}
