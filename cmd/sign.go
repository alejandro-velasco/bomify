package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/sign"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/signature"
)

const signShort = "Add signatures to a published package"

const signLong = `Sign signs a package that's already published: <reference> in a
registry, or with --input every package tagged in a "bomify save"
tarball. Only manifests are fetched, never layers, so co-signers can sign
at different times, in different environments, each with only its own
key, for a trust rule requiring several signers.

It signs as --sign and --signer do for "bomify push": the package, and
each of its vulnerability report and VEX referrers, which pulls verify
separately. Signatures already there are kept. Build provenance isn't
attested again: a rule requiring it accepts one trusted attestation.

With --input, the signed tarball is written to --output, or back over
--input if --output isn't given.`

const signExample = `  # Add the security team's signature to a package CI already signed
  bomify sign registry.example.com/myapp:1.0 --signer security

  # Sign with a plugin directly
  bomify sign registry.example.com/myapp:1.0 --sign sigstore --sign-option key=security.key

  # Sign every package in a tarball, in place
  bomify sign --input myapp.tar --signer security

  # Write the signed tarball elsewhere
  bomify sign --input myapp.tar --output myapp-signed.tar --signer security`

type signOptions struct {
	sign   signFlags
	input  string
	output string
}

func signCmd() *cobra.Command {
	opts := &signOptions{}

	cmd := &cobra.Command{
		Use:     "sign [<reference>]",
		Short:   signShort,
		Long:    signLong,
		Example: signExample,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runSign(cmd, args, opts); err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			return nil
		},
	}

	opts.sign.register(cmd)
	cmd.Flags().StringVarP(&opts.input, "input", "i", "", "sign every package in this \"bomify save\" tarball instead of a registry reference")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "write the signed tarball here instead of back over --input")

	return cmd
}

func runSign(cmd *cobra.Command, args []string, opts *signOptions) error {
	logger := logging.FromContext(cmd.Context())

	if len(args) == 0 && opts.input == "" {
		return errors.New("give a <reference>, or --input with a tarball")
	}
	if len(args) == 1 && opts.input != "" {
		return errors.New("give a <reference> or --input, not both")
	}
	if opts.output != "" && opts.input == "" {
		return errors.New("--output needs --input")
	}

	plugins, err := opts.sign.plugins(dataDir)
	if err != nil {
		return err
	}
	if len(plugins) == 0 {
		return errors.New("nothing to sign with: give --sign or --signer")
	}
	signer, _, err := signature.NewSigners(layout.Plugins(dataDir), plugins, logger)
	if err != nil {
		return err
	}

	if opts.input != "" {
		return signArchive(cmd, opts, signer, logger)
	}

	ref := args[0]
	repo, err := newRepository(ref)
	if err != nil {
		return err
	}
	result, err := sign.Sign(cmd.Context(), repo, ref, signer)
	if err != nil {
		return err
	}
	logSigned(logger, ref, result)
	return nil
}

// signArchive signs every package in opts.input, writing the tarball to
// opts.output, or back over opts.input, atomically, so a failure never
// leaves it half written.
func signArchive(cmd *cobra.Command, opts *signOptions, signer transfer.Signer, logger *slog.Logger) error {
	in, err := os.Open(opts.input)
	if err != nil {
		return err
	}
	defer in.Close()

	output := opts.output
	if output == "" {
		output = opts.input
	}
	var results []sign.TaggedResult
	err = fsutil.WriteAtomic(output, func(w io.Writer) error {
		var signErr error
		results, signErr = sign.SignArchive(cmd.Context(), in, w, signer)
		// Closed before WriteAtomic renames over it, which Windows can't
		// do to a file that's still open.
		in.Close()
		return signErr
	})
	if err != nil {
		return err
	}

	for _, result := range results {
		logSigned(logger, result.Tag, result.Result)
	}
	logger.Info("signed tarball written", "output", output)
	return nil
}

func logSigned(logger *slog.Logger, ref string, result sign.Result) {
	logger.Info("package signed", "reference", ref, "manifest", result.Manifest.Digest.String(), "referrers", len(result.Referrers))
}
