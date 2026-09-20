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

The endpoint used is chosen per component by its plugin kind: pass
one or more --remote kind=endpoint flags (e.g. --remote
oci=registry.example.com --remote helm=charts.example.com/helm). A
kind with no matching --remote falls back to the data directory's
conf/distribution.json.`

const distributeExample = `  # Distribute myapp:latest using endpoints from "bomify distribution create"
  bomify distribute myapp:latest

  # Distribute with explicit per-kind remotes
  bomify distribute myapp:latest --remote oci=registry.example.com --remote helm=charts.example.com/helm

  # Distribute 4 components concurrently
  bomify distribute myapp:latest --concurrency 4`

type distributeOptions struct {
	tag         string
	remotes     map[string]string
	concurrency int
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

	return distributeCmd
}

func runDistribute(opts *distributeOptions, logger *slog.Logger) error {
	sbomHash, err := build.ResolveTag(dataDir, opts.tag)
	if err != nil {
		return err
	}

	fallback, err := distribution.Remotes(dataDir)
	if err != nil {
		return err
	}

	return forEachComponent(build.ManifestPath(dataDir, sbomHash), logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		kind, path, err := resolvePlugin(component, log)
		if err != nil {
			return err
		}

		remote, err := resolveRemote(kind, opts.remotes, fallback)
		if err != nil {
			return err
		}

		log.Info("delegating to plugin", "kind", kind, "path", path, "remote", remote)

		result, err := plugin.Push(path, component, dataDir, remote, log)
		if err != nil {
			return err
		}

		log.Info("push complete", "output", result.OutputPath, "message", result.Message)

		return nil
	})
}

// resolveRemote picks the endpoint for kind, preferring flags (from --remote)
// over fallback (from conf/distribution.json), and erroring if neither has
// an entry for kind.
func resolveRemote(kind string, flags, fallback map[string]string) (string, error) {
	if remote, ok := flags[kind]; ok {
		return remote, nil
	}
	if remote, ok := fallback[kind]; ok {
		return remote, nil
	}
	return "", fmt.Errorf("no remote configured for kind %q: pass --remote %s=<endpoint> or add it to %s", kind, kind, distribution.ConfigPath(dataDir))
}
