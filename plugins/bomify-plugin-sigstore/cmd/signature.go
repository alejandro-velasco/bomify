package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-sigstore/internal/sigstore"
)

// signatureCmd groups the signing plugin contract's subcommands (see
// plugins/SIGNING-CONTRACT.md), kept independent of any other plugin
// class this binary might also implement.
func signatureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signature",
		Short: "Signing subcommands — see plugins/SIGNING-CONTRACT.md",
	}

	cmd.AddCommand(newSignatureSignCmd())
	cmd.AddCommand(newSignatureVerifyCmd())
	cmd.AddCommand(newSignatureSupportedTypesCmd())

	return cmd
}

// newSignatureSignCmd builds the `signature sign` subcommand.
func newSignatureSignCmd() *cobra.Command {
	var (
		payloadPath string
		reference   string
		options     []string
	)

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a payload, printing a Sigstore bundle as the envelope",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := sigstore.ParseOptions(options)
			if err != nil {
				return err
			}
			payload, err := os.ReadFile(payloadPath)
			if err != nil {
				return fmt.Errorf("read payload: %w", err)
			}

			envelope, err := sigstore.Sign(cmd.Context(), payload, opts)
			if err != nil {
				return err
			}

			result := pluginlib.SignResult{
				ArtifactType: sigstore.BundleMediaType,
				MediaType:    sigstore.BundleMediaType,
				Envelope:     envelope,
			}
			return result.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&payloadPath, "payload", "", "file holding the payload to sign (required)")
	cmd.Flags().StringVar(&reference, "reference", "", "reference of the package being signed (required)")
	cmd.Flags().StringArrayVar(&options, "option", nil, "a key=value option (repeatable): key, or for keyless identity-token, certificate-identity[-regexp], certificate-oidc-issuer[-regexp]")
	_ = cmd.MarkFlagRequired("payload")
	_ = cmd.MarkFlagRequired("reference")

	return cmd
}

// newSignatureVerifyCmd builds the `signature verify` subcommand.
func newSignatureVerifyCmd() *cobra.Command {
	var (
		payloadPath  string
		envelopePath string
		mediaType    string
		reference    string
		options      []string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a Sigstore bundle envelope over a payload",
		RunE: func(cmd *cobra.Command, args []string) error {
			if mediaType != sigstore.BundleMediaType {
				return fmt.Errorf("unsupported envelope media type %q, want %q", mediaType, sigstore.BundleMediaType)
			}
			opts, err := sigstore.ParseOptions(options)
			if err != nil {
				return err
			}
			payload, err := os.ReadFile(payloadPath)
			if err != nil {
				return fmt.Errorf("read payload: %w", err)
			}
			envelope, err := os.ReadFile(envelopePath)
			if err != nil {
				return fmt.Errorf("read envelope: %w", err)
			}

			signer, err := sigstore.Verify(payload, envelope, opts)
			if err != nil {
				return err
			}

			result := pluginlib.VerifyResult{Signer: signer}
			return result.Print(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&payloadPath, "payload", "", "file holding the payload the envelope should sign (required)")
	cmd.Flags().StringVar(&envelopePath, "envelope", "", "file holding the signature envelope (required)")
	cmd.Flags().StringVar(&mediaType, "media-type", "", "the envelope's media type (required)")
	cmd.Flags().StringVar(&reference, "reference", "", "reference of the package being verified (required)")
	cmd.Flags().StringArrayVar(&options, "option", nil, "a key=value option (repeatable): key, or for keyless identity-token, certificate-identity[-regexp], certificate-oidc-issuer[-regexp]")
	for _, name := range []string{"payload", "envelope", "media-type", "reference"} {
		_ = cmd.MarkFlagRequired(name)
	}

	return cmd
}

// newSignatureSupportedTypesCmd builds the `signature supported-types`
// subcommand.
func newSignatureSupportedTypesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "supported-types",
		Short: "Report the referrer artifact types this plugin verifies",
		RunE: func(cmd *cobra.Command, args []string) error {
			result := pluginlib.SupportedSignatureTypesResult{ArtifactTypes: []string{sigstore.BundleMediaType}}
			return result.Print(cmd.OutOrStdout())
		},
	}
}
