// Package cmd contains the bomify-plugin-oci CLI commands.
package cmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-oci/internal/image"
)

// NewRootCmd builds the bomify-plugin-oci root command, implementing the
// component plugin contract (see plugins/contracts/component/v1/CONTRACT.md).
func NewRootCmd() *cobra.Command {
	return plugin.NewRootCommand("oci", "bomify plugin for container/OCI image components",
		plugin.ComponentCommand(component{}, plugin.ComponentHelp{
			Pull: "Download the component's image and save it as an OCI Image Layout",
			Pack: "Describe the image a prior pull wrote into --input as it is, keeping its digest",
		}))
}

// component implements plugin.ComponentPlugin, and plugin.ComponentPacker,
// over internal/image.
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
	return image.Pull(ref, req.Output, req.Logger, req.Progress)
}

func (component) Pack(_ context.Context, req plugin.PackRequest) (*plugin.PackResult, error) {
	return image.Pack(req.Input, req.Logger)
}
