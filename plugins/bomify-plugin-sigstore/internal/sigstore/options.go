package sigstore

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Option keys this plugin understands, passed as --option key=value.
const (
	// OptionKey is a PEM private key (sign) or public key (verify) file —
	// a Sigstore-format encrypted key ("ENCRYPTED SIGSTORE PRIVATE KEY"),
	// an encrypted PKCS#8 key, or a plain PKCS#8/EC/PKCS#1 PEM key. Its
	// presence selects key-based signing; its absence selects keyless
	// signing.
	OptionKey = "key"
	// OptionIdentityToken is the OIDC identity token keyless signing
	// exchanges for a Fulcio certificate; SIGSTORE_ID_TOKEN is used if
	// it's unset. Prefer the environment variable: an option risks being
	// recorded, e.g. in shell history.
	OptionIdentityToken = "identity-token"
	// OptionCertificateIdentity is the exact certificate identity (SAN) a
	// keyless signature must carry — for a GitHub Actions workflow,
	// "https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>".
	OptionCertificateIdentity = "certificate-identity"
	// OptionCertificateIdentityRegexp is a regular expression the
	// certificate identity must match, instead of an exact one.
	OptionCertificateIdentityRegexp = "certificate-identity-regexp"
	// OptionCertificateOIDCIssuer is the exact OIDC issuer a keyless
	// signature's certificate must name — for GitHub Actions,
	// "https://token.actions.githubusercontent.com".
	OptionCertificateOIDCIssuer = "certificate-oidc-issuer"
	// OptionCertificateOIDCIssuerRegexp is a regular expression the OIDC
	// issuer must match, instead of an exact one.
	OptionCertificateOIDCIssuerRegexp = "certificate-oidc-issuer-regexp"
)

// passwordEnv names the environment variable an encrypted private key's
// password is read from.
const passwordEnv = "SIGSTORE_PASSWORD"

// idTokenEnv names the environment variable keyless signing reads its
// OIDC identity token from when no identity-token option is given.
const idTokenEnv = "SIGSTORE_ID_TOKEN"

// keylessOptions are the options only keyless signing or verification
// uses.
var keylessOptions = []string{
	OptionIdentityToken,
	OptionCertificateIdentity,
	OptionCertificateIdentityRegexp,
	OptionCertificateOIDCIssuer,
	OptionCertificateOIDCIssuerRegexp,
}

// Options are the parsed --option values this plugin was given.
type Options map[string]string

// ParseOptions parses each "key=value" in raw, rejecting any key this
// plugin doesn't understand rather than silently ignoring it — a typo in
// a verification option must never quietly weaken what's checked. For
// the same reason, a key option can't be combined with any keyless one:
// whichever set was meant, the other would otherwise be ignored.
func ParseOptions(raw []string) (Options, error) {
	opts := Options{}
	for _, option := range raw {
		key, value, ok := strings.Cut(option, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("option %q: want key=value", option)
		}
		if key != OptionKey && !isKeylessOption(key) {
			return nil, fmt.Errorf("unknown option %q", key)
		}
		if value == "" {
			return nil, fmt.Errorf("option %q: empty value", key)
		}
		opts[key] = value
	}

	if _, hasKey := opts[OptionKey]; hasKey {
		for _, keyless := range keylessOptions {
			if _, ok := opts[keyless]; ok {
				return nil, errors.New("key can't be combined with keyless options (" + strings.Join(keylessOptions, ", ") + ")")
			}
		}
	}
	return opts, nil
}

// identityToken returns the OIDC identity token keyless signing uses: the
// identity-token option, else SIGSTORE_ID_TOKEN, else "". Where the token
// comes from — a CI system's own OIDC provider, typically — is the
// caller's business, not this plugin's.
func (o Options) identityToken() string {
	if token := o[OptionIdentityToken]; token != "" {
		return token
	}
	return os.Getenv(idTokenEnv)
}

// isKeylessOption reports whether key is one of keylessOptions.
func isKeylessOption(key string) bool {
	for _, option := range keylessOptions {
		if key == option {
			return true
		}
	}
	return false
}
