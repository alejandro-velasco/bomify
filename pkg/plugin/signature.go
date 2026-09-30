package plugin

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// SigningPlugin is a signing plugin's own logic (see
// plugins/SIGNING-CONTRACT.md), for SignatureCommand to expose as the
// contract's "signature sign"/"signature verify"/"signature
// supported-types". SignatureCommand reads the payload and envelope
// files itself, so a SigningPlugin only ever deals in bytes.
type SigningPlugin interface {
	// Sign signs payload on behalf of the package being published as
	// req.Reference.
	Sign(ctx context.Context, req SignRequest) (SignResult, error)
	// Verify reports who signed req.Envelope over req.Payload, failing if
	// it isn't a valid signature by a signer req.Options trusts.
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
	// SupportedTypes reports the referrer artifact types Verify accepts.
	SupportedTypes(ctx context.Context) (SupportedSignatureTypesResult, error)
}

// SignRequest is one "signature sign" invocation.
type SignRequest struct {
	Payload []byte
	// PayloadType, if set, asks for a DSSE envelope over Payload with this
	// payload type (e.g. "application/vnd.in-toto+json" for an in-toto
	// attestation) instead of a signature over the raw payload. A plugin
	// that can't produce one must fail.
	PayloadType string
	Reference   string
	// Options are the --option values, each "key=value", unparsed.
	Options []string
}

// VerifyRequest is one "signature verify" invocation.
type VerifyRequest struct {
	Payload   []byte
	Envelope  []byte
	MediaType string
	Reference string
	// Options are the --option values, each "key=value", unparsed.
	Options []string
}

// SigningHelp is the plugin-specific help text SignatureCommand shows.
type SigningHelp struct {
	// Sign and Verify are each subcommand's short description.
	Sign, Verify string
	// Options describes the --option keys the plugin understands.
	Options string
}

// SignatureCommand builds the "signature" command implementing the
// signing plugin contract around p.
func SignatureCommand(p SigningPlugin, help SigningHelp) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signature",
		Short: "Signing subcommands — see plugins/SIGNING-CONTRACT.md",
	}
	optionUsage := "a key=value option (repeatable): " + help.Options

	var (
		signReq     SignRequest
		signPayload string
	)
	sign := &cobra.Command{
		Use:   "sign",
		Short: help.Sign,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if signReq.Payload, err = readFile("payload", signPayload); err != nil {
				return err
			}
			result, err := p.Sign(cmd.Context(), signReq)
			return print(cmd, result, err)
		},
	}
	sign.Flags().StringVar(&signPayload, "payload", "", "file holding the payload to sign (required)")
	sign.Flags().StringVar(&signReq.Reference, "reference", "", "reference of the package being signed (required)")
	sign.Flags().StringVar(&signReq.PayloadType, "payload-type", "", "sign the payload as a DSSE envelope of this payload type, e.g. application/vnd.in-toto+json")
	sign.Flags().StringArrayVar(&signReq.Options, "option", nil, optionUsage)
	for _, name := range []string{"payload", "reference"} {
		_ = sign.MarkFlagRequired(name)
	}

	var (
		verifyReq                     VerifyRequest
		verifyPayload, verifyEnvelope string
	)
	verify := &cobra.Command{
		Use:   "verify",
		Short: help.Verify,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if verifyReq.Payload, err = readFile("payload", verifyPayload); err != nil {
				return err
			}
			if verifyReq.Envelope, err = readFile("envelope", verifyEnvelope); err != nil {
				return err
			}
			result, err := p.Verify(cmd.Context(), verifyReq)
			return print(cmd, result, err)
		},
	}
	verify.Flags().StringVar(&verifyPayload, "payload", "", "file holding the payload the envelope should sign (required)")
	verify.Flags().StringVar(&verifyEnvelope, "envelope", "", "file holding the signature envelope (required)")
	verify.Flags().StringVar(&verifyReq.MediaType, "media-type", "", "the envelope's media type (required)")
	verify.Flags().StringVar(&verifyReq.Reference, "reference", "", "reference of the package being verified (required)")
	verify.Flags().StringArrayVar(&verifyReq.Options, "option", nil, optionUsage)
	for _, name := range []string{"payload", "envelope", "media-type", "reference"} {
		_ = verify.MarkFlagRequired(name)
	}

	supported := &cobra.Command{
		Use:   "supported-types",
		Short: "Report the referrer artifact types this plugin verifies",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := p.SupportedTypes(cmd.Context())
			return print(cmd, result, err)
		},
	}

	cmd.AddCommand(sign, verify, supported)
	return cmd
}

func readFile(what, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", what, err)
	}
	return data, nil
}
