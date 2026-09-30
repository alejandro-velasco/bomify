// Package cmd contains the bomify-plugin-sigstore CLI commands.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-sigstore/internal/sigstore"
)

// NewRootCmd builds the bomify-plugin-sigstore root command, implementing
// the signing contract (see plugins/SIGNING-CONTRACT.md).
func NewRootCmd() *cobra.Command {
	return pluginlib.NewRootCommand("sigstore", "bomify signing plugin producing Sigstore bundles",
		pluginlib.SignatureCommand(signer{}, pluginlib.SigningHelp{
			Sign:    "Sign a payload, printing a Sigstore bundle as the envelope",
			Verify:  "Verify a Sigstore bundle envelope over a payload",
			Options: "key, or for keyless identity-token, certificate-identity[-regexp], certificate-oidc-issuer[-regexp]",
		}))
}

// signer implements pluginlib.SigningPlugin over internal/sigstore.
type signer struct{}

func (signer) Sign(ctx context.Context, req pluginlib.SignRequest) (pluginlib.SignResult, error) {
	opts, err := sigstore.ParseOptions(req.Options)
	if err != nil {
		return pluginlib.SignResult{}, err
	}
	envelope, err := sigstore.Sign(ctx, req.Payload, opts)
	if err != nil {
		return pluginlib.SignResult{}, err
	}
	return pluginlib.SignResult{
		ArtifactType: sigstore.BundleMediaType,
		MediaType:    sigstore.BundleMediaType,
		Envelope:     envelope,
	}, nil
}

func (signer) Verify(_ context.Context, req pluginlib.VerifyRequest) (pluginlib.VerifyResult, error) {
	if req.MediaType != sigstore.BundleMediaType {
		return pluginlib.VerifyResult{}, fmt.Errorf("unsupported envelope media type %q, want %q", req.MediaType, sigstore.BundleMediaType)
	}
	opts, err := sigstore.ParseOptions(req.Options)
	if err != nil {
		return pluginlib.VerifyResult{}, err
	}
	signer, err := sigstore.Verify(req.Payload, req.Envelope, opts)
	return pluginlib.VerifyResult{Signer: signer}, err
}

func (signer) SupportedTypes(context.Context) (pluginlib.SupportedSignatureTypesResult, error) {
	return pluginlib.SupportedSignatureTypesResult{ArtifactTypes: []string{sigstore.BundleMediaType}}, nil
}
