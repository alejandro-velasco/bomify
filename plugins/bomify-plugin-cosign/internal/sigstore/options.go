package sigstore

import (
	"fmt"
	"os"
	"strings"
)

// Option keys this plugin understands, passed as --option key=value.
const (
	// OptionKey is a PEM private key (sign) or public key (verify) file
	// — any key `cosign generate-key-pair` produces, or a plain
	// PKCS#8/EC/PKCS#1 PEM key. Its presence selects key-based signing;
	// its absence selects keyless signing.
	OptionKey = "key"
	// OptionIdentityToken is the OIDC identity token keyless signing
	// exchanges for a Fulcio certificate. SIGSTORE_ID_TOKEN is used
	// instead if unset, which is preferable: an option risks being
	// recorded, e.g. in shell history.
	OptionIdentityToken = "identity-token"
	// OptionCertificateIdentity is the exact certificate identity (SAN)
	// a keyless signature must carry.
	OptionCertificateIdentity = "certificate-identity"
	// OptionCertificateIdentityRegexp is a regular expression the
	// certificate identity must match, instead of an exact one.
	OptionCertificateIdentityRegexp = "certificate-identity-regexp"
	// OptionCertificateOIDCIssuer is the exact OIDC issuer a keyless
	// signature's certificate must name.
	OptionCertificateOIDCIssuer = "certificate-oidc-issuer"
	// OptionCertificateOIDCIssuerRegexp is a regular expression the
	// OIDC issuer must match, instead of an exact one.
	OptionCertificateOIDCIssuerRegexp = "certificate-oidc-issuer-regexp"
)

// passwordEnv names the environment variable an encrypted private key's
// password is read from — the same one cosign itself uses.
const passwordEnv = "COSIGN_PASSWORD"

// idTokenEnv names the environment variable keyless signing reads its
// OIDC identity token from when no identity-token option is given.
const idTokenEnv = "SIGSTORE_ID_TOKEN"

var knownOptions = map[string]bool{
	OptionKey:                         true,
	OptionIdentityToken:               true,
	OptionCertificateIdentity:         true,
	OptionCertificateIdentityRegexp:   true,
	OptionCertificateOIDCIssuer:       true,
	OptionCertificateOIDCIssuerRegexp: true,
}

// Options are the parsed --option values this plugin was given.
type Options map[string]string

// ParseOptions parses each "key=value" in raw, rejecting any key this
// plugin doesn't understand rather than silently ignoring it — a typo in
// a verification option must never quietly weaken what's checked.
func ParseOptions(raw []string) (Options, error) {
	opts := Options{}
	for _, option := range raw {
		key, value, ok := strings.Cut(option, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("option %q: want key=value", option)
		}
		if !knownOptions[key] {
			return nil, fmt.Errorf("unknown option %q", key)
		}
		opts[key] = value
	}
	return opts, nil
}

// identityToken returns the keyless signing identity token, from the
// identity-token option or SIGSTORE_ID_TOKEN.
func (o Options) identityToken() string {
	if token := o[OptionIdentityToken]; token != "" {
		return token
	}
	return os.Getenv(idTokenEnv)
}
