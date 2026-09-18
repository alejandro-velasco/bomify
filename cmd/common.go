package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/alejandro-velasco/bomify/internal/auth"
	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

// forEachComponent calls fn for every component in the SBOM at sbomPath,
// up to concurrency at a time (concurrency < 1 runs sequentially).
func forEachComponent(sbomPath string, logger *slog.Logger, concurrency int, fn func(component cdx.Component, log *slog.Logger) error) error {
	logger.Debug("loading sbom", "path", sbomPath)

	bom, err := sbom.Load(sbomPath)
	if err != nil {
		return fmt.Errorf("load sbom: %w", err)
	}

	name := "unknown"
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		name = bom.Metadata.Component.Name
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	logger.Info("loaded sbom", "name", name, "components", componentCount, "concurrency", concurrency)

	if bom.Components == nil {
		return nil
	}

	if concurrency < 1 {
		concurrency = 1
	}

	var g errgroup.Group
	g.SetLimit(concurrency)

	for _, component := range *bom.Components {
		g.Go(func() error {
			log := logger.With("component", component.Name, "version", component.Version)
			if err := fn(component, log); err != nil {
				return fmt.Errorf("%s@%s: %w", component.Name, component.Version, err)
			}
			return nil
		})
	}

	return g.Wait()
}

// resolvePlugin detects the plugin kind for component and locates its
// binary on PATH, logging along the way.
func resolvePlugin(component cdx.Component, log *slog.Logger) (kind, path string, err error) {
	kind, err = plugin.Detect(component)
	if err != nil {
		log.Error("failed to detect plugin kind", "error", err)
		return "", "", fmt.Errorf("detect plugin kind: %w", err)
	}

	path, err = plugin.Find(kind)
	if err != nil {
		return "", "", err
	}

	return kind, path, nil
}

// newRepository builds a remote.Repository for ref, authenticating with
// whatever credentials `bomify login` (or `docker login` — they share a
// store) has for its registry. A registry with no stored credentials is
// accessed anonymously.
func newRepository(ref string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference %s: %w", ref, err)
	}

	client, err := auth.Client()
	if err != nil {
		return nil, err
	}
	repo.Client = client

	return repo, nil
}

// resolvedDataDir mirrors root.go's PersistentPreRun default, which
// completion invocations skip (cobra's __complete runs without it).
func resolvedDataDir(cmd *cobra.Command) string {
	if dir, err := cmd.Flags().GetString("data-dir"); err == nil && dir != "" {
		return dir
	}
	if dir, err := defaultDataDir(); err == nil {
		return dir
	}
	return ""
}

// completeLocalTags is a cobra ValidArgsFunction shared by every command
// that takes an already-tagged local package (push, distribute, save,
// package remove/rmp).
func completeLocalTags(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	repos, err := build.ReadRepositories(resolvedDataDir(cmd))
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var tags []string
	for repo, versions := range repos {
		for version := range versions {
			tag := repo + ":" + version
			if strings.HasPrefix(tag, toComplete) {
				tags = append(tags, tag)
			}
		}
	}

	return tags, cobra.ShellCompDirectiveNoFileComp
}
