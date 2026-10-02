package signature

import (
	"log/slog"

	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// signPayload invokes the signing plugin's "signature sign" over the
// payload in payloadFile, on behalf of the package being published as ref
// (see plugins/SIGNING-CONTRACT.md). Each of options ("key=value") is
// passed through, unparsed, as its own --option flag.
func signPayload(path, payloadFile, ref string, options []string, logger *slog.Logger) (pluginlib.SignResult, error) {
	logger.Debug("signing", "path", path, "reference", ref)
	args := append([]string{"signature", "sign", "--payload", payloadFile, "--reference", ref}, optionArgs(options)...)
	return plugin.Invoke[pluginlib.SignResult](path, args...)
}

// attestStatement invokes the signing plugin's "signature attest" over
// the in-toto statement in statementFile, as signPayload does.
func attestStatement(path, statementFile, ref string, options []string, logger *slog.Logger) (pluginlib.SignResult, error) {
	logger.Debug("attesting", "path", path, "reference", ref)
	args := append([]string{"signature", "attest", "--statement", statementFile, "--reference", ref}, optionArgs(options)...)
	return plugin.Invoke[pluginlib.SignResult](path, args...)
}

// verifyEnvelope invokes the signing plugin's "signature verify", asking whether
// the envelope in envelopeFile (of media type mediaType) is a trusted
// signature over the payload in payloadFile for the package being
// restored as ref. A nil error means it is; the plugin reports anything
// else — a bad signature, an untrusted signer, a malformed envelope — by
// failing.
func verifyEnvelope(path, payloadFile, envelopeFile, mediaType, ref string, options []string, logger *slog.Logger) (pluginlib.VerifyResult, error) {
	logger.Debug("verifying signature", "path", path, "reference", ref, "mediaType", mediaType)
	args := append([]string{
		"signature", "verify",
		"--payload", payloadFile,
		"--envelope", envelopeFile,
		"--media-type", mediaType,
		"--reference", ref,
	}, optionArgs(options)...)
	return plugin.Invoke[pluginlib.VerifyResult](path, args...)
}

// verifyAttestationEnvelope invokes the signing plugin's "signature
// verify-attestation", asking whether the envelope in envelopeFile (of
// media type mediaType) is a trusted attestation about subject, and for
// the statement it signs.
func verifyAttestationEnvelope(path, envelopeFile, mediaType, subject, ref string, options []string, logger *slog.Logger) (pluginlib.VerifyAttestationResult, error) {
	logger.Debug("verifying attestation", "path", path, "reference", ref, "mediaType", mediaType)
	args := append([]string{
		"signature", "verify-attestation",
		"--envelope", envelopeFile,
		"--media-type", mediaType,
		"--subject", subject,
		"--reference", ref,
	}, optionArgs(options)...)
	return plugin.Invoke[pluginlib.VerifyAttestationResult](path, args...)
}

// supportedTypes invokes the signing plugin's "signature
// supported-types", which reports the referrer artifact types its
// "signature verify" understands.
func supportedTypes(path string, logger *slog.Logger) (pluginlib.SupportedSignatureTypesResult, error) {
	logger.Debug("querying supported signature types", "path", path)
	return plugin.Invoke[pluginlib.SupportedSignatureTypesResult](path, "signature", "supported-types")
}

// optionArgs expands each "key=value" option into its own --option flag.
func optionArgs(options []string) []string {
	args := make([]string, 0, 2*len(options))
	for _, option := range options {
		args = append(args, "--option", option)
	}
	return args
}
