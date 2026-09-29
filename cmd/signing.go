package cmd

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/signature"
)

// signFlags are the --sign/--sign-option flags push and save share.
type signFlags struct {
	plugin  string
	options []string
}

func (f *signFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.plugin, "sign", "", "sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer")
	cmd.Flags().StringArrayVar(&f.options, "sign-option", nil, "a key=value option passed through to the signing plugin (repeatable; e.g. key=cosign.key)")
}

// signer returns the transfer.Signer f describes, or nil if --sign wasn't
// given.
func (f *signFlags) signer(logger *slog.Logger) (transfer.Signer, error) {
	if f.plugin == "" {
		if len(f.options) > 0 {
			return nil, fmt.Errorf("--sign-option given without --sign")
		}
		return nil, nil
	}
	if err := validateOptions("--sign-option", f.options); err != nil {
		return nil, err
	}
	return signature.NewSigner(plugin.Dir(dataDir), signature.Plugin{Kind: f.plugin, Options: f.options}, logger)
}

// verifyFlags are the --verify/--verify-option/--insecure-skip-verify
// flags pull and load share.
type verifyFlags struct {
	plugin  string
	options []string
	skip    bool
}

func (f *verifyFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.plugin, "verify", "", "require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any \"bomify trust\" rule")
	cmd.Flags().StringArrayVar(&f.options, "verify-option", nil, "a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)")
	cmd.Flags().BoolVar(&f.skip, "insecure-skip-verify", false, "restore the package without verifying its signature, even if a \"bomify trust\" rule requires it")
	cmd.MarkFlagsMutuallyExclusive("verify", "insecure-skip-verify")
}

// verifier returns the transfer.Verifier enforcing f together with
// baseDir's trust rules (see signature.Policy).
func (f *verifyFlags) verifier(baseDir string, logger *slog.Logger) (transfer.Verifier, error) {
	if f.plugin == "" && len(f.options) > 0 {
		return nil, fmt.Errorf("--verify-option given without --verify")
	}
	if err := validateOptions("--verify-option", f.options); err != nil {
		return nil, err
	}

	rules, err := signature.Read(baseDir)
	if err != nil {
		return nil, err
	}

	policy := signature.Policy{
		Verifier: signature.Plugin{Kind: f.plugin, Options: f.options},
		Rules:    rules,
		Skip:     f.skip,
	}
	return signature.NewVerifier(plugin.Dir(baseDir), policy, logger), nil
}

// validateOptions requires every one of options to be "key=value".
func validateOptions(flag string, options []string) error {
	for _, option := range options {
		if key, _, ok := strings.Cut(option, "="); !ok || key == "" {
			return fmt.Errorf("%s %q: want key=value", flag, option)
		}
	}
	return nil
}
