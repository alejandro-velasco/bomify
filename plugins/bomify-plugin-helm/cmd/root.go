// Package cmd contains the bomify-plugin-helm CLI commands.
package cmd

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-helm/internal/chart"
)

// NewRootCmd builds the bomify-plugin-helm root command, implementing two
// entirely independent plugin contracts: the component contract (see
// plugins/COMPONENT-CONTRACT.md) and SBOM generation (see sbomCmd).
func NewRootCmd() *cobra.Command {
	return plugin.NewRootCommand("helm", "bomify plugin for Helm chart components",
		plugin.ComponentCommand(component{}, plugin.ComponentHelp{
			Pull:       "Download the chart from its HTTP repository or OCI registry and save it as a .tgz",
			Push:       "Push the chart a prior pull wrote into --input to an OCI registry",
			Remote:     "Report the chart repository this component's purl names",
			RemoteFlag: `OCI registry/repository to push to, e.g. "oci://registry.example.com/charts"`,
		}),
		sbomCmd())
}

// component implements plugin.ComponentPlugin over internal/chart.
type component struct{}

func (component) Pull(_ context.Context, req plugin.PullRequest) (*plugin.Result, error) {
	ref, err := resolve(req.Purl, req.Logger)
	if err != nil {
		return nil, err
	}
	if req.Check {
		return chart.CheckPull(ref, req.Logger)
	}
	return chart.Pull(ref, req.Output, req.Logger)
}

func (component) Push(_ context.Context, req plugin.PushRequest) (*plugin.Result, error) {
	ref, err := resolve(req.Purl, req.Logger)
	if err != nil {
		return nil, err
	}
	if req.Check {
		return chart.CheckPush(ref, req.Remote, req.Logger)
	}
	return chart.Push(req.Input, ref, req.Remote, req.Logger)
}

func (component) Remote(_ context.Context, purl string, logger *slog.Logger) (string, error) {
	ref, err := resolve(purl, logger)
	return ref.RepositoryURL, err
}

func resolve(purl string, logger *slog.Logger) (chart.Ref, error) {
	logger.Info("resolving purl", "purl", purl)
	ref, err := chart.Resolve(purl)
	if err != nil {
		return chart.Ref{}, err
	}
	logger.Info("resolved reference", "repository_url", ref.RepositoryURL, "oci", ref.OCI)
	return ref, nil
}
