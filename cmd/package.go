package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"bomify/internal/build"
	"bomify/internal/logging"
)

// packageCmd builds the `bomify package` command group: operations on
// individual packages, as opposed to `bomify packages`' listing of all of
// them (mirroring `docker image prune`/`docker image rm` alongside
// `docker images`).
func packageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package",
		Short: "Manage individual bomify packages",
	}

	cmd.AddCommand(packagePruneCmd())
	cmd.AddCommand(packageRemoveCmd())

	return cmd
}

// packagePruneCmd builds the `bomify package prune` command.
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

	fmt.Fprintf(cmd.OutOrStdout(), "Removed %d item(s)\n", len(result.Removed))

	return nil
}

// packageRemoveCmd builds the `bomify package remove` command.
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
// `bomify package remove`, mirroring how `docker rmi` shortens `docker
// image rm`.
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

// runPackageRemove untags every given tag, continuing past any individual
// failure (so one bad tag in a batch doesn't block the rest — matching
// `docker rmi`'s per-image reporting), then prunes once at the end to
// reclaim whatever just became unreferenced.
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

	return nil
}
