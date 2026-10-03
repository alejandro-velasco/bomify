package security

import (
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// scanComponent invokes the scanning plugin's "security scan" for
// component, which reports every vulnerability its purl is affected by —
// each with Affects already set by the plugin, never by bomify (see
// plugins/contracts/security/v1/CONTRACT.md).
func scanComponent(path string, component cdx.Component, logger *slog.Logger) (pluginlib.SecurityResult, error) {
	logger.Info("scanning component", "purl", component.PackageURL)
	return plugin.Invoke[pluginlib.SecurityResult](path, pluginlib.SecuritySubcommand, "scan", "--purl", component.PackageURL)
}

// supportedComponents invokes the scanning plugin's "security
// supported-components", once per Scan, to learn which purl types are
// worth dispatching to scanComponent at all.
func supportedComponents(path string, logger *slog.Logger) (pluginlib.SupportedComponentsResult, error) {
	logger.Info("querying supported components", "path", path)
	return plugin.Invoke[pluginlib.SupportedComponentsResult](path, pluginlib.SecuritySubcommand, "supported-components")
}
