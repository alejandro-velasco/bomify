package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/save"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/security"
)

const saveShort = "Save packages to a tarball"

const saveLong = `Save packages one or more tagged packages into a single tarball — an
OCI image-layout archive containing each package's manifest and
components, plus a referrer carrying any local vulnerability reports of
its components (see "bomify push") — that
"bomify load" can restore on any machine, with no registry involved. A
component shared by more than one given tag is stored once. Writes to
stdout if --output isn't given.

--sign signs each saved package with a signing plugin, exactly as
"bomify push --sign" would, the signature travelling inside the
tarball for "bomify load --verify" to check.

--scan, --fail-on, --ignore, --vex, and --skip-scan gate each tag
before anything is written, exactly as "bomify push" does, as does a
"bomify security policy" rule listing "push" in its --on.`

const saveExample = `  # Save one package to stdout, redirected to a file
  bomify save myapp:latest > packages.tar

  # Save several packages to a file
  bomify save myapp:v1 myapp:v2 --output packages.tar

  # Archive up to 6 layers concurrently
  bomify save myapp:latest --output packages.tar --concurrency 6

  # Sign each saved package with a cosign key
  bomify save myapp:latest --output packages.tar --sign sigstore --sign-option key=cosign.key`

type saveOptions struct {
	output      string
	concurrency int
	sign        signFlags
	scan        scanFlags
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
	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 3, "number of layers to archive concurrently")
	opts.sign.register(cmd)
	opts.scan.register(cmd)

	return cmd
}

func runSave(cmd *cobra.Command, tags []string, opts *saveOptions) error {
	logger := logging.FromContext(cmd.Context())

	signer, err := opts.sign.signer(logger)
	if err != nil {
		return err
	}

	// Each tag is gated before anything is written, as "bomify push"
	// gates it — so a failing tag never reaches the tarball.
	for _, tag := range tags {
		p, err := opts.scan.plan(tag, security.HookPush, logger)
		if err != nil {
			return err
		}
		if !p.active() {
			continue
		}
		sbomHash, err := build.ResolveTag(dataDir, tag)
		if err != nil {
			return err
		}
		if err := gateLocalPackage(cmd.ErrOrStderr(), p, sbomHash, opts.concurrency, logger.With("tag", tag)); err != nil {
			return fmt.Errorf("not saved: %s: %w", tag, err)
		}
	}

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

	err = save.Save(cmd.Context(), dataDir, tags, w, opts.concurrency, progress, transfer.Hooks{Sign: signer})
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
