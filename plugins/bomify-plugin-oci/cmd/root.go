// Package cmd contains the bomify-plugin-oci CLI commands.
package cmd

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-oci/internal/image"
)

// NewRootCmd builds the bomify-plugin-oci root command, implementing the
// component plugin contract (see plugins/COMPONENT-CONTRACT.md).
func NewRootCmd() *cobra.Command {
	return plugin.NewRootCommand("oci", "bomify plugin for container/OCI image components",
		plugin.ComponentCommand(component{}, plugin.ComponentHelp{
			Pull:       "Download the component's image and save it as an OCI Image Layout",
			Push:       "Push the OCI Image Layout a prior pull wrote into --input to a remote endpoint",
			Remote:     "Report the registry/namespace this component's purl names",
			RemoteFlag: "remote registry/repository to push to",
		}))
}

// component implements plugin.ComponentPlugin over internal/image.
type component struct{}

func (component) Pull(_ context.Context, req plugin.PullRequest) (*plugin.Result, error) {
	req.Logger.Info("resolving purl", "purl", req.Purl)
	ref, err := image.Resolve(req.Purl)
	if err != nil {
		return nil, err
	}
	req.Logger.Info("resolved reference", "ref", ref)

	if req.Check {
		return image.CheckPull(ref, req.Logger)
	}
	return image.Pull(ref, req.Output, req.Logger)
}

func (component) Push(_ context.Context, req plugin.PushRequest) (*plugin.Result, error) {
	if req.Check {
		return image.CheckPush(req.Purl, req.Remote, req.Logger)
	}
	return image.Push(req.Input, req.Purl, req.Remote, req.Logger)
}

func (component) Remote(_ context.Context, purl string, logger *slog.Logger) (string, error) {
	location, err := image.Location(purl)
	if err != nil {
		return "", err
	}
	logger.Info("resolved location", "location", location)
	return location, nil
}
