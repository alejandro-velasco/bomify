package cmd

import (
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/distribution"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

const distributeShort = "Publish a locally available package to a remote endpoint"

const distributeLong = `Distribute resolves <tag> to the SBOM manifest a prior "bomify build" or
"bomify pull" recorded for it (see "bomify tag" / "bomify packages")
and publishes each component that SBOM describes to a remote
endpoint.

The endpoint used is chosen per component: pass one or more --remote
kind=endpoint flags (e.g. --remote oci=registry.example.com --remote
helm=charts.example.com/helm) for a quick one-off override by plugin
kind. A kind with no matching --remote falls back to the rules in the
data directory's conf/distribution.json (see "bomify distribution
create"). A rule scoped with --match acts as a mirror: it doesn't just
pick an endpoint, it carries over whatever of the component's origin
came after the matched prefix, so distinct repositories under that
prefix still land at distinct destinations under the mirror instead of
all colliding on one endpoint.

--check verifies push permission to every component's resolved remote —
an inexpensive check each plugin performs itself, without publishing
anything.`

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

	return forEachComponent(build.ManifestPath(dataDir, sbomHash), logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
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
	return "", fmt.Errorf("no remote configured for kind %q origin %q: pass --remote %s=<endpoint> or add a matching rule to %s", kind, origin, kind, distribution.ConfigPath(dataDir))
}
