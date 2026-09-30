// Package cmd contains the bomify-plugin-grype CLI commands.
package cmd

import (
	"context"

	"github.com/spf13/cobra"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-grype/internal/scan"
)

// NewRootCmd builds the bomify-plugin-grype root command, implementing
// the security scanning contract (see plugins/SECURITY-CONTRACT.md).
func NewRootCmd() *cobra.Command {
	return pluginlib.NewRootCommand("grype", "bomify security scanning plugin backed by grype",
		pluginlib.SecurityCommand(scanner{}, pluginlib.SecurityHelp{
			Scan: "Report the vulnerabilities the given purl is affected by, via grype's vulnerability database",
		}))
}

// scanner implements pluginlib.SecurityPlugin over internal/scan.
type scanner struct{}

func (scanner) Scan(_ context.Context, purl string) (pluginlib.SecurityResult, error) {
	provider, err := scan.Load()
	if err != nil {
		return pluginlib.SecurityResult{}, err
	}
	defer provider.Close()

	return scan.Purl(provider, purl)
}

func (scanner) SupportedComponents(context.Context) (pluginlib.SupportedComponentsResult, error) {
	return pluginlib.SupportedComponentsResult{Types: scan.SupportedTypes(), Scans: []string{"sca"}}, nil
}
