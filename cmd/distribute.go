package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/distribution"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

const distributeShort = "Publish a locally available package to a remote endpoint"

const distributeLong = `Distribute publishes each component of the package <tag> to its own
remote endpoint, as opposed to "bomify push", which publishes the
package as one artifact.

Each component's endpoint is the --remote given for its plugin kind,
else the best matching rule from "bomify distribution create".

--check verifies push permission to every resolved endpoint without
publishing anything.`

const distributeExample = `  # Distribute myapp:latest using the rules from "bomify distribution create"
  bomify distribute myapp:latest

  # Distribute with explicit per-kind remotes, overriding any rule
  bomify distribute myapp:latest --remote oci=registry.example.com --remote helm=charts.example.com/helm

  # Distribute 4 components concurrently
  bomify distribute myapp:latest --concurrency 4

  # Verify push permission to every component's remote, without publishing anything
  bomify distribute myapp:latest --check`

type distributeOptions struct {
	tag         string
	remotes     map[string]string
	concurrency int
	check       bool
}

func distributeCmd() *cobra.Command {
	distributeOpts := &distributeOptions{}

	distributeCmd := &cobra.Command{
		Use:     "distribute <tag>",
		Short:   distributeShort,
		Long:    distributeLong,
		Example: distributeExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			distributeOpts.tag = args[0]
			if err := runDistribute(distributeOpts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("distribute: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	distributeCmd.Flags().StringToStringVarP(&distributeOpts.remotes, "remote", "r", map[string]string{}, "kind=endpoint remote mapping (repeatable); kinds not given fall back to <data-dir>/conf/distribution.json")
	distributeCmd.Flags().IntVarP(&distributeOpts.concurrency, "concurrency", "c", 1, "number of components to push concurrently")
	distributeCmd.Flags().BoolVar(&distributeOpts.check, "check", false, "verify push permission to every component's remote, without publishing anything")

	return distributeCmd
}

func runDistribute(opts *distributeOptions, logger *slog.Logger) error {
	sbomHash, err := build.ResolveTag(dataDir, opts.tag)
	if err != nil {
		return err
	}

	rules, err := distribution.Read(dataDir)
	if err != nil {
		return err
	}

	return forEachComponent(layout.Manifest(dataDir, sbomHash), logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		// A plugin binary has no remote of its own to republish to: it
		// only ever travels inside its package (see "bomify plugin
		// install").
		if _, isBinary, err := plugin.ParseBinary(component); err != nil {
			return err
		} else if isBinary {
			log.Info("skipping plugin binary component", "purl", component.PackageURL)
			return nil
		}

		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		origin, err := plugin.Remote(path, component, dataDir, log)
		if err != nil {
			return err
		}

		remote, err := resolveRemote(kind, origin, opts.remotes, rules)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "origin", origin, "remote", remote)

		if opts.check {
			result, err := plugin.CheckPush(path, component, dataDir, remote, log)
			if err != nil {
				return err
			}
			log.Info("check complete", "output", result.OutputPath, "message", result.Message)
			return nil
		}

		result, err := plugin.Push(path, component, dataDir, remote, log)
		if err != nil {
			return err
		}

		log.Info("push complete", "output", result.OutputPath, "message", result.Message)

		return nil
	})
}

// resolveRemote picks the endpoint for a component of kind and origin
// (see plugin.Remote), preferring flags (from --remote, a one-off
// override by kind only) over the best-matching rule in rules (from
// conf/distribution.json, see distribution.Resolve), and erroring if
// neither has one.
func resolveRemote(kind, origin string, flags map[string]string, rules distribution.Config) (string, error) {
	if remote, ok := flags[kind]; ok {
		return remote, nil
	}
	if remote, ok := distribution.Resolve(rules, kind, origin); ok {
		return remote, nil
	}
	return "", fmt.Errorf("no remote configured for kind %q origin %q: pass --remote %s=<endpoint> or add a matching rule to %s", kind, origin, kind, layout.DistributionConfig(dataDir))
}
