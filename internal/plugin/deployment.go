package plugin

import (
	"log/slog"

	"github.com/alejandro-velasco/bomify/internal/layout"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// Deployment is one call of a deployment plugin's "deployment generate"
// (see plugins/contracts/deployment/v1/CONTRACT.md).
type Deployment struct {
	// Name is the deployment's name.
	Name string
	// Package is the path of the package description, and Output the
	// directory to write into.
	Package string
	Output  string
	// Config and Overlays are the deployment's files; Options its
	// key=value settings.
	Config   string
	Overlays []string
	Options  []string
}

// Generate invokes the deployment plugin at path's "deployment generate"
// for deployment, logging as runComponent does under baseDir, and returns
// what it reports it wrote.
func Generate(path string, deployment Deployment, baseDir string, logger *slog.Logger) (*pluginlib.DeploymentResult, error) {
	logArgs, stopLog, err := pluginLog(layout.DeploymentLog(baseDir, deployment.Name), "deployment "+deployment.Name, logger)
	if err != nil {
		return nil, err
	}
	defer stopLog()

	args := []string{pluginlib.DeploymentSubcommand, "generate", "--name", deployment.Name, "--package", deployment.Package, "--output", deployment.Output}
	if deployment.Config != "" {
		args = append(args, "--config", deployment.Config)
	}
	for _, overlay := range deployment.Overlays {
		args = append(args, "--overlay", overlay)
	}
	for _, option := range deployment.Options {
		args = append(args, "--option", option)
	}
	args = append(args, logArgs...)

	result, err := Invoke[pluginlib.DeploymentResult](path, args...)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
