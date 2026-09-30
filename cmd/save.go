package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/save"
)

const saveShort = "Save packages to a tarball"

const saveLong = `Save writes one or more local packages, with their vulnerability
reports and signatures, to a single tarball (an OCI image layout) that
"bomify load" can restore anywhere without a registry. Shared components
are stored once. It writes to stdout unless --output is given.

--sign and --vex work as for "bomify push"; signatures and VEX travel
inside the tarball.`

const saveExample = `  # Save one package to stdout, redirected to a file
  bomify save myapp:latest > packages.tar

  # Save several packages to a file
  bomify save myapp:v1 myapp:v2 --output packages.tar

  # Archive up to 6 layers concurrently
  bomify save myapp:latest --output packages.tar --concurrency 6

  # Sign each saved package with a cosign key
  bomify save myapp:latest --output packages.tar --sign sigstore --sign-option key=cosign.key`

type saveOptions struct {
	publishFlags
	output string
}

func saveCmd() *cobra.Command {
	opts := &saveOptions{}

	cmd := &cobra.Command{
		Use:     "save <tag>...",
		Short:   saveShort,
		Long:    saveLong,
		Example: saveExample,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runSave(cmd, args, opts); err != nil {
				return fmt.Errorf("save: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "write the tarball here instead of stdout")
	opts.register(cmd, "archive", "")

	return cmd
}

func runSave(cmd *cobra.Command, tags []string, opts *saveOptions) error {
	logger := logging.FromContext(cmd.Context())

	// Resolved before creating --output, so a bad --sign leaves no empty
	// tarball behind.
	transferOpts, done, err := opts.options(cmd, logger)
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			done()
			return fmt.Errorf("create %s: %w", opts.output, err)
		}
		defer f.Close()
		w = f
	}

	err = save.Save(cmd.Context(), dataDir, tags, w, transferOpts)
	done()
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
