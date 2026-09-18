package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/save"
)

type loadOptions struct {
	input       string
	concurrency int
}

func loadCmd() *cobra.Command {
	opts := &loadOptions{}

	cmd := &cobra.Command{
		Use:   "load",
		Short: "Load packages from a tarball",
		Long:  "Load restores every package a `bomify save` tarball contains into the data directory, exactly as `bomify pull` would have for each, and records each of their tags. Reads from stdin if --input isn't given, mirroring `docker load`.",
		Args:  cobra.NoArgs,
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
