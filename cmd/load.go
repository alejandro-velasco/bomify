package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/save"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/prefix"
)

const loadShort = "Load packages from a tarball"

const loadLong = `Load restores every package a "bomify save" tarball contains into the
data directory, exactly as "bomify pull" would have for each, and
records each of their tags. Reads from stdin if --input isn't given.

Signature verification works exactly as for "bomify pull": --verify,
else any "bomify trust" rule matching each tag, checked before
anything of that package is restored. --insecure-skip-verify bypasses
a matching trust rule.

--quiet prints only each restored package's pinned reference,
<repository>@<digest>, one per tag on stdout — no progress bars, and no
logging but warnings and errors.`

const loadExample = `  # Load a tarball piped in from stdin
  cat packages.tar | bomify load

  # Load a tarball from a file
  bomify load --input packages.tar

  # Restore up to 6 layers concurrently
  bomify load --input packages.tar --concurrency 6

  # Require every package to carry a signature made with a cosign key
  bomify load --input packages.tar --verify sigstore --verify-option key=cosign.pub

  # Print just the pinned reference of each package loaded
  bomify load --input packages.tar --quiet`

type loadOptions struct {
	input       string
	concurrency int
	verify      verifyFlags
	quiet       bool
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
	cmd.Flags().BoolVarP(&opts.quiet, "quiet", "q", false, "print only each restored package's pinned reference (<repository>@<digest>), with no progress or informational logging")
	opts.verify.register(cmd)

	return cmd
}

func runLoad(cmd *cobra.Command, opts *loadOptions) error {
	logger := logging.FromContext(cmd.Context())
	if opts.quiet {
		logger = logging.WarningsOnly(logger)
	}

	verifier, err := opts.verify.verifier(dataDir, logger)
	if err != nil {
		return err
	}

	r := cmd.InOrStdin()
	if opts.input != "" {
		f, err := os.Open(opts.input)
		if err != nil {
			return fmt.Errorf("open %s: %w", opts.input, err)
		}
		defer f.Close()
		r = f
	}

	var progress transfer.ProgressFunc
	if !opts.quiet {
		mb := newMultiBar(cmd.ErrOrStderr())
		defer mb.Wait()
		progress = newProgressFunc(mb)
	}

	loaded, err := save.Load(cmd.Context(), dataDir, r, opts.concurrency, progress, verifier)
	if err != nil {
		return err
	}

	tags := make([]string, 0, len(loaded))
	for _, l := range loaded {
		tags = append(tags, l.Tag)
		if l.ReportsSkipped != nil {
			logger.Warn("vulnerability reports not restored", "tag", l.Tag, "error", l.ReportsSkipped)
		}
		if opts.quiet {
			fmt.Fprintf(cmd.OutOrStdout(), "%s@%s\n", prefix.Repository(l.Tag), l.ManifestDigest)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "Loaded:", l.Tag)
		}
	}
	logger.Info("loaded", "tags", tags)

	return nil
}
