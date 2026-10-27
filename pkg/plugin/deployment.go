package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// DeploymentPackage is the package description bomify passes a deployment
// plugin's "deployment generate" as --package (see
// plugins/contracts/deployment/v1/CONTRACT.md): the package, verified, and
// where each of its components is in the registry it's deployed from.
type DeploymentPackage struct {
	// Reference is the package, as given to "bomify deploy generate".
	Reference string `json:"reference"`
	// Repository is its repository, where every component is.
	Repository string `json:"repository"`
	// Digest is the package index's digest: what was verified.
	Digest string `json:"digest"`
	// Components are every component, in the SBOM's order.
	Components []DeploymentComponent `json:"components"`
}

// DeploymentComponent is one component of a DeploymentPackage.
type DeploymentComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl"`
	// ArtifactType is its manifest's artifact type, if it has one, e.g. a
	// Helm chart's config media type.
	ArtifactType string `json:"artifactType,omitempty"`
	// Digest is its manifest's digest.
	Digest string `json:"digest"`
	// Reference is "<repository>@<digest>": it, pinned, in the package's
	// repository, where it always is.
	Reference string `json:"reference"`
	// Tagged is where it's tagged, if it is.
	Tagged *TaggedReference `json:"tagged,omitempty"`
}

// TaggedReference is where a component is tagged: Registry, Repository,
// and Tag apart, and Reference whole.
type TaggedReference struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Reference  string `json:"reference"`
}

// DeploymentResult is what "deployment generate" prints: the files it
// wrote, relative to --output, and, optionally, what to do with them.
type DeploymentResult struct {
	Files        []string `json:"files"`
	Instructions string   `json:"instructions,omitempty"`
}

// DeploymentPlugin is a deployment plugin's own logic (see
// plugins/contracts/deployment/v1/CONTRACT.md), for DeploymentCommand to
// expose as the contract's "deployment generate".
type DeploymentPlugin interface {
	// Generate writes what req.Name deploys into req.Output, and reports
	// the files it wrote.
	Generate(ctx context.Context, req GenerateRequest) (*DeploymentResult, error)
}

// GenerateRequest is one "deployment generate" invocation.
type GenerateRequest struct {
	// Name is the deployment's name.
	Name string
	// Package is the package description, parsed.
	Package DeploymentPackage
	// Output is the (existing, empty) directory to write into.
	Output string
	// Config is the deployment's config file, if it has one, and Overlays
	// the files to lay over it, in order.
	Config   string
	Overlays []string
	// Options are the deployment's settings.
	Options map[string]string
	// Logger writes to the invocation's --log file (see OpenLog).
	Logger *slog.Logger
}

// DeploymentHelp is the plugin-specific help text DeploymentCommand shows.
type DeploymentHelp struct {
	// Generate is "deployment generate"'s short description.
	Generate string
}

// DeploymentCommand builds the "deployment" command implementing the
// deployment plugin contract around p.
func DeploymentCommand(p DeploymentPlugin, help DeploymentHelp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   DeploymentSubcommand,
		Short: "Deployment plugin subcommands — see plugins/contracts/deployment/v1/CONTRACT.md",
	}

	var (
		packageFile string
		options     []string
		logFile     string
		logColor    bool
		req         GenerateRequest
	)
	generate := &cobra.Command{
		Use:   "generate",
		Short: help.Generate,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, closeLog, err := OpenLog(logFile, logColor)
			if err != nil {
				return err
			}
			defer closeLog()

			pkg, err := ReadDeploymentPackage(packageFile)
			if err != nil {
				return err
			}
			parsed, err := parseOptions(options)
			if err != nil {
				return err
			}
			req.Package = pkg
			req.Options = parsed
			req.Logger = logger
			result, err := p.Generate(cmd.Context(), req)
			return print(cmd, result, err)
		},
	}
	flags := generate.Flags()
	flags.StringVar(&req.Name, "name", "", "the deployment's name (required)")
	flags.StringVar(&packageFile, "package", "", "the package description, a JSON file (required)")
	flags.StringVar(&req.Output, "output", "", "the directory to write into (required)")
	flags.StringVar(&req.Config, "config", "", "the deployment's config file")
	flags.StringArrayVar(&req.Overlays, "overlay", nil, "a file to lay over the config's output (repeatable, in order)")
	flags.StringArrayVar(&options, "option", nil, "a key=value setting (repeatable)")
	flags.StringVar(&logFile, "log", "", "file to write plugin logs to (required)")
	flags.BoolVar(&logColor, "log-color", false, "enable ANSI color codes in the log output")
	for _, name := range []string{"name", "package", "output", "log"} {
		_ = generate.MarkFlagRequired(name)
	}

	cmd.AddCommand(generate)
	return cmd
}

// ReadDeploymentPackage reads the package description at path, ignoring
// fields it doesn't know, as the contract asks of a plugin.
func ReadDeploymentPackage(path string) (DeploymentPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DeploymentPackage{}, fmt.Errorf("read package description: %w", err)
	}
	var pkg DeploymentPackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return DeploymentPackage{}, fmt.Errorf("parse package description %s: %w", path, err)
	}
	return pkg, nil
}

// parseOptions parses each "key=value" of options, failing on one
// without "=" or given twice.
func parseOptions(options []string) (map[string]string, error) {
	parsed := map[string]string{}
	for _, option := range options {
		key, value, ok := strings.Cut(option, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("--option %q: want key=value", option)
		}
		if _, given := parsed[key]; given {
			return nil, fmt.Errorf("--option %s given more than once", key)
		}
		parsed[key] = value
	}
	return parsed, nil
}
