package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/signature"
)

// signFlags are the --sign/--sign-option/--signer flags push and save
// share.
type signFlags struct {
	kind    string
	options []string
	signers []string
}

func (f *signFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.kind, "sign", "", "sign the package with this signing plugin (bomify-plugin-<kind>, e.g. sigstore), attaching the signature as an OCI referrer")
	cmd.Flags().StringArrayVar(&f.options, "sign-option", nil, "a key=value option passed through to the --sign plugin (repeatable; e.g. key=cosign.key)")
	cmd.Flags().StringArrayVar(&f.signers, "signer", nil, "also sign the package as this signer from \"bomify signer create\" (repeatable)")
}

// plugins returns the signing plugins the flags describe: --sign's with
// --sign-option, then each --signer's from baseDir, none if neither flag
// was given.
func (f *signFlags) plugins(baseDir string) ([]signature.Plugin, error) {
	if f.kind == "" && len(f.options) > 0 {
		return nil, fmt.Errorf("--sign-option given without --sign")
	}
	if err := validateOptions("--sign-option", f.options); err != nil {
		return nil, err
	}

	var plugins []signature.Plugin
	if f.kind != "" {
		plugin := signature.Plugin{
			Kind:    f.kind,
			Options: f.options,
		}
		plugins = append(plugins, plugin)
	}
	// Without --signer, signers.json isn't needed, so a push that doesn't
	// use it can't fail on reading it.
	if len(f.signers) == 0 {
		return plugins, nil
	}

	profiles, err := signature.ReadProfiles(baseDir)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, name := range f.signers {
		if seen[name] {
			return nil, fmt.Errorf("--signer %q given more than once", name)
		}
		seen[name] = true
		profile, ok := signature.FindProfile(profiles, name)
		if !ok {
			return nil, fmt.Errorf("--signer %q: no such signer (see \"bomify signer list\")", name)
		}
		plugins = append(plugins, profile.Plugin())
	}
	return plugins, nil
}

// verifyFlags are the --verify/--verify-option/--verify-provenance/
// --insecure-skip-verify flags pull and load share.
type verifyFlags struct {
	plugin     string
	options    []string
	provenance bool
	skip       bool
}

func (f *verifyFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.plugin, "verify", "", "require a signature this signing plugin (bomify-plugin-<kind>, e.g. sigstore) verifies, overriding any \"bomify trust\" rule")
	cmd.Flags().StringArrayVar(&f.options, "verify-option", nil, "a key=value option passed through to the --verify plugin (repeatable; e.g. key=cosign.pub)")
	cmd.Flags().BoolVar(&f.provenance, "verify-provenance", false, "also require the package's build provenance, attested by a signer the verifying plugin trusts")
	cmd.Flags().BoolVar(&f.skip, "insecure-skip-verify", false, "restore the package without verifying its signature or provenance, even if a \"bomify trust\" rule requires it")
	cmd.MarkFlagsMutuallyExclusive("verify", "insecure-skip-verify")
	cmd.MarkFlagsMutuallyExclusive("verify-provenance", "insecure-skip-verify")
}

// policy returns the signature.Policy f describes together with
// baseDir's trust rules.
func (f *verifyFlags) policy(baseDir string) (signature.Policy, error) {
	if f.plugin == "" && len(f.options) > 0 {
		return signature.Policy{}, fmt.Errorf("--verify-option given without --verify")
	}
	if err := validateOptions("--verify-option", f.options); err != nil {
		return signature.Policy{}, err
	}

	rules, err := signature.ReadResolved(baseDir)
	if err != nil {
		return signature.Policy{}, err
	}

	return signature.Policy{
		Verifier:   signature.Plugin{Kind: f.plugin, Options: f.options},
		Rules:      rules,
		Skip:       f.skip,
		Provenance: f.provenance,
	}, nil
}

// validateOptions requires every one of options to be "key=value", with
// neither side empty: an empty value (e.g. an unset shell variable in
// "certificate-identity=$ME") would otherwise be saved or passed on, only
// to fail — or worse, be read as "anything" — much later.
func validateOptions(flag string, options []string) error {
	for _, option := range options {
		key, value, ok := strings.Cut(option, "=")
		if !ok || key == "" {
			return fmt.Errorf("%s %q: want key=value", flag, option)
		}
		if value == "" {
			return fmt.Errorf("%s %q: empty value", flag, option)
		}
	}
	return nil
}
