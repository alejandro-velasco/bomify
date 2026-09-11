package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
)

func tagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag <source-tag> <destination-tag>",
		Short: "Tag creates a new tag pointing at an existing package",
		Long:  "Tag creates <destination-tag> as an alias for the package that <source-tag> currently resolves to, similar to `docker tag`.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTag(args[0], args[1])
		},
	}

	return cmd
}

func runTag(sourceTag, destTag string) error {
	sbomHash, err := build.ResolveTag(dataDir, sourceTag)
	if err != nil {
		return fmt.Errorf("tag: %w", err)
	}

	if err := build.UpdateRepositories(dataDir, []string{destTag}, sbomHash); err != nil {
		return fmt.Errorf("tag: %w", err)
	}

	return nil
}
