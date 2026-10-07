// Package cmd contains the bomify-plugin-huggingface CLI commands.
package cmd

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-huggingface/internal/hub"
)

// NewRootCmd builds the bomify-plugin-huggingface root command,
// implementing the component plugin contract (see
// plugins/contracts/component/v1/CONTRACT.md).
func NewRootCmd() *cobra.Command {
	help := plugin.ComponentHelp{
		Pull:       "Download the model repository at the purl's commit from the Hub",
		Push:       "Upload a pulled model repository to --remote as one commit",
		Remote:     "Report the hub and namespace this component's purl names",
		RemoteFlag: "the hub and namespace to upload into, e.g. huggingface.co/my-org; the repository keeps the purl's name, and is created private if it doesn't exist",
	}
	return plugin.NewRootCommand("huggingface", "bomify plugin for Hugging Face Hub models",
		plugin.ComponentCommand(component{}, help),
		sbomCmd())
}

// component implements plugin.ComponentPlugin over internal/hub.
type component struct{}

func (component) Pull(ctx context.Context, req plugin.PullRequest) (*plugin.Result, error) {
	ref, err := resolve(req.Purl, req.Logger)
	if err != nil {
		return nil, err
	}
	client, err := hub.NewClient(ref.Endpoint, req.Logger)
	if err != nil {
		return nil, err
	}
	if req.Check {
		return hub.CheckPull(ctx, client, ref)
	}
	return hub.Pull(ctx, client, ref, req.Output, req.Logger)
}

func (component) Push(ctx context.Context, req plugin.PushRequest) (*plugin.Result, error) {
	ref, err := resolve(req.Purl, req.Logger)
	if err != nil {
		return nil, err
	}
	endpoint, _, err := hub.ParseRemote(req.Remote)
	if err != nil {
		return nil, err
	}
	client, err := hub.NewClient(endpoint, req.Logger)
	if err != nil {
		return nil, err
	}
	if req.Check {
		return hub.CheckPush(ctx, client, ref, req.Remote)
	}
	return hub.Push(ctx, client, ref, req.Input, req.Remote, req.Logger)
}

func (component) Remote(_ context.Context, purl string, logger *slog.Logger) (string, error) {
	ref, err := resolve(purl, logger)
	if err != nil {
		return "", err
	}
	return ref.Remote(), nil
}

func resolve(purl string, logger *slog.Logger) (hub.Ref, error) {
	logger.Info("resolving purl", "purl", purl)
	ref, err := hub.Resolve(purl)
	if err != nil {
		return hub.Ref{}, err
	}
	logger.Info("resolved repository", "repository", ref.RepoID(), "revision", ref.Revision, "endpoint", ref.Endpoint)
	return ref, nil
}
