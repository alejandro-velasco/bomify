package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
)

const tagShort = "Create a new tag pointing at an existing package"

const tagLong = `Tag creates <destination-tag> as an alias for the package that
<source-tag> currently resolves to.`

const tagExample = `  # Point a new tag at an existing package
  bomify tag myapp:v1 myapp:latest

  # Re-tag a package under a different repository name
  bomify tag myapp:latest registry.example.com/myapp:latest`

func tagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tag <source-tag> <destination-tag>",
		Short:   tagShort,
		Long:    tagLong,
		Example: tagExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTag(args[0], args[1])
		},
		ValidArgsFunction: completeSourceTag,
	}

	return cmd
}

// completeSourceTag completes only <source-tag>; <destination-tag> is a new
// name the user is choosing, not one that already exists.
func completeSourceTag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeLocalTags(cmd, args, toComplete)
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
