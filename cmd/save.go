package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/save"
)

type saveOptions struct {
	output      string
	concurrency int
}

func saveCmd() *cobra.Command {
	opts := &saveOptions{}

	cmd := &cobra.Command{
		Use:   "save <tag>...",
		Short: "Save packages to a tarball",
		Long:  "Save packages one or more tagged packages into a single tarball — an OCI image-layout archive containing each package's manifest and components — that `bomify load` can restore on any machine, with no registry involved. A component shared by more than one given tag is stored once. Writes to stdout if --output isn't given, mirroring `docker save`.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runSave(cmd, args, opts); err != nil {
				return fmt.Errorf("save: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "write the tarball here instead of stdout")
	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 3, "number of layers to archive concurrently")

	return cmd
}

func runSave(cmd *cobra.Command, tags []string, opts *saveOptions) error {
	logger := logging.FromContext(cmd.Context())

	w := cmd.OutOrStdout()
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			return fmt.Errorf("create %s: %w", opts.output, err)
		}
		defer f.Close()
		w = f
	}

	mb := newMultiBar(cmd.ErrOrStderr())
	progress := newProgressFunc(mb)

	err := save.Save(cmd.Context(), dataDir, tags, w, opts.concurrency, progress)
	mb.Wait()
	if err != nil {
		return err
	}

	destination := "stdout"
	if opts.output != "" {
		destination = opts.output
	}
	logger.Info("saved", "tags", tags, "output", destination)

	return nil
}
