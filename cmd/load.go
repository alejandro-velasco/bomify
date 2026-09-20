package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/save"
)

const loadShort = "Load packages from a tarball"

const loadLong = `Load restores every package a "bomify save" tarball contains into the
data directory, exactly as "bomify pull" would have for each, and
records each of their tags. Reads from stdin if --input isn't given.`

const loadExample = `  # Load a tarball piped in from stdin
  cat packages.tar | bomify load

  # Load a tarball from a file
  bomify load --input packages.tar

  # Restore up to 6 layers concurrently
  bomify load --input packages.tar --concurrency 6`

type loadOptions struct {
	input       string
	concurrency int
}

func loadCmd() *cobra.Command {
	opts := &loadOptions{}

	cmd := &cobra.Command{
		Use:     "load",
		Short:   loadShort,
		Long:    loadLong,
		Example: loadExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runLoad(cmd, opts); err != nil {
				return fmt.Errorf("load: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.input, "input", "i", "", "read the tarball from here instead of stdin")
	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 3, "number of layers to restore concurrently")

	return cmd
}

func runLoad(cmd *cobra.Command, opts *loadOptions) error {
	logger := logging.FromContext(cmd.Context())

	r := cmd.InOrStdin()
	if opts.input != "" {
		f, err := os.Open(opts.input)
		if err != nil {
			return fmt.Errorf("open %s: %w", opts.input, err)
		}
		defer f.Close()
		r = f
	}

	mb := newMultiBar(cmd.ErrOrStderr())
	progress := newProgressFunc(mb)

	tags, err := save.Load(cmd.Context(), dataDir, r, opts.concurrency, progress)
	mb.Wait()
	if err != nil {
		return err
	}

	for _, tag := range tags {
		fmt.Fprintln(cmd.OutOrStdout(), "Loaded:", tag)
	}
	logger.Info("loaded", "tags", tags)

	return nil
}
