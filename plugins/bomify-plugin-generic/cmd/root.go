// Package cmd contains the bomify-plugin-generic CLI commands.
package cmd

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/internal/artifact"
)

// NewRootCmd builds the bomify-plugin-generic root command, implementing
// the component plugin contract (see plugins/COMPONENT-CONTRACT.md).
func NewRootCmd() *cobra.Command {
	return plugin.NewRootCommand("generic", "bomify plugin for plain HTTP GET/PUT artifacts",
		plugin.ComponentCommand(component{}, plugin.ComponentHelp{
			Pull:       "GET the artifact's download_url and save it",
			Push:       "PUT the artifact a prior pull wrote into --input to --remote",
			Remote:     "Report the download URL this component's purl names",
			RemoteFlag: "destination URL to PUT the artifact to",
		}))
}

// component implements plugin.ComponentPlugin over internal/artifact.
type component struct{}

func (component) Pull(_ context.Context, req plugin.PullRequest) (*plugin.Result, error) {
	ref, err := resolve(req.Purl, req.Logger)
	if err != nil {
		return nil, err
	}
	if req.Check {
		return artifact.CheckPull(ref, req.Logger)
	}
	return artifact.Pull(ref, req.Output, req.Logger)
}

func (component) Push(_ context.Context, req plugin.PushRequest) (*plugin.Result, error) {
	if req.Check {
		return artifact.CheckPush(req.Remote, req.Logger)
	}
	ref, err := resolve(req.Purl, req.Logger)
	if err != nil {
		return nil, err
	}
	return artifact.Push(req.Input, ref, req.Remote, req.Logger)
}

func (component) Remote(_ context.Context, purl string, logger *slog.Logger) (string, error) {
	ref, err := resolve(purl, logger)
	return ref.DownloadURL, err
}

func resolve(purl string, logger *slog.Logger) (artifact.Ref, error) {
	logger.Info("resolving purl", "purl", purl)
	ref, err := artifact.Resolve(purl)
	if err != nil {
		return artifact.Ref{}, err
	}
	logger.Info("resolved reference", "download_url", ref.DownloadURL)
	return ref, nil
}
