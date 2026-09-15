package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
)

func packageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package",
		Short: "Manage individual bomify packages",
	}

	cmd.AddCommand(packagePruneCmd())
	cmd.AddCommand(packageRemoveCmd())
	cmd.AddCommand(packageManifestCmd())

	return cmd
}

func packagePruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove packages not associated with any tag",
		Long:  "Prune removes every manifest and layer in the data directory that isn't reachable from a tag currently recorded in repositories.json — mirroring `docker image prune`. A component still used by any tagged package, even one also used by an otherwise-unreferenced package, is left alone.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackagePrune(cmd); err != nil {
				return fmt.Errorf("package prune: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func runPackagePrune(cmd *cobra.Command) error {
	logger := logging.FromContext(cmd.Context())

	result, err := build.Prune(dataDir)
	if err != nil {
		return err
	}

	for _, item := range result.Removed {
		logger.Info("removed", "kind", item.Kind, "path", item.Path)
	}
	for _, path := range result.Skipped {
		logger.Info("skipped (pull in flight)", "path", path)
	}
	for _, hash := range result.Unprotected {
		logger.Warn("could not parse this build's manifest; its components could not be protected from pruning", "hash", hash)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Removed %d item(s)\n", len(result.Removed))

	return nil
}

// packageManifestCmd builds the `bomify package manifest` command.
func packageManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest <reference>",
		Short: "Print a remote package's CycloneDX manifest",
		Long:  "Manifest fetches <reference> from an OCI registry and writes its aggregate CycloneDX SBOM manifest (the artifact's config blob) verbatim to stdout, without pulling any of its layers or writing anything to the data directory.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackageManifest(cmd, args[0]); err != nil {
				return fmt.Errorf("package manifest: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func runPackageManifest(cmd *cobra.Command, ref string) error {
	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	data, err := pull.Manifest(cmd.Context(), repo, ref)
	if err != nil {
		return err
	}

	_, err = cmd.OutOrStdout().Write(data)
	return err
}

func packageRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove <tag>...",
		Aliases: []string{"rm"},
		Short:   "Remove packages by tag",
		Long:    "Remove untags each given <tag> and reclaims any manifest or component no longer used by a remaining tag — mirroring `docker image rm`/`docker rmi` (also available as the top-level shorthand `bomify rmp`).",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackageRemove(cmd, args); err != nil {
				return fmt.Errorf("package remove: %w", err)
			}
			return nil
		},
	}

	return cmd
}

// rmpCmd builds the top-level `bomify rmp` command: a shorthand for
// `bomify package remove`
func rmpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rmp <tag>...",
		Short: "Remove packages by tag (shorthand for `bomify package remove`)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackageRemove(cmd, args); err != nil {
				return fmt.Errorf("rmp: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func runPackageRemove(cmd *cobra.Command, tags []string) error {
	logger := logging.FromContext(cmd.Context())

	var failed []string
	for _, tag := range tags {
		if err := build.RemoveTag(dataDir, tag); err != nil {
			logger.Error("failed to remove", "tag", tag, "error", err)
			failed = append(failed, tag)
			continue
		}
		fmt.Fprintln(cmd.OutOrStdout(), tag)
	}

	if err := pruneAfterRemove(logger); err != nil {
		return err
	}

	if len(failed) > 0 {
		return fmt.Errorf("failed to remove: %s", strings.Join(failed, ", "))
	}

	return nil
}

func pruneAfterRemove(logger *slog.Logger) error {
	result, err := build.Prune(dataDir)
	if err != nil {
		return fmt.Errorf("prune after remove: %w", err)
	}

	for _, item := range result.Removed {
		logger.Info("removed", "kind", item.Kind, "path", item.Path)
	}
	for _, hash := range result.Unprotected {
		logger.Warn("could not parse this build's manifest; its components could not be protected from pruning", "hash", hash)
	}

	return nil
}
