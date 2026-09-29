package sigstore

import (
	"errors"
	"fmt"
	"strings"
)

// OptionKey is the one option this plugin understands, passed as
// --option key=<path>: a PEM private key (sign) or public key (verify)
// file — a Sigstore-format encrypted key ("ENCRYPTED SIGSTORE PRIVATE
// KEY"), an encrypted PKCS#8 key, or a plain PKCS#8/EC/PKCS#1 PEM key.
// It's required for both signing and verifying.
const OptionKey = "key"

// passwordEnv names the environment variable an encrypted private key's
// password is read from.
const passwordEnv = "SIGSTORE_PASSWORD"

// Options are the parsed --option values this plugin was given.
type Options map[string]string

// ParseOptions parses each "key=value" in raw, rejecting any key this
// plugin doesn't understand rather than silently ignoring it — a typo in
// a verification option must never quietly weaken what's checked — and
// requiring the key option itself.
func ParseOptions(raw []string) (Options, error) {
	opts := Options{}
	for _, option := range raw {
		key, value, ok := strings.Cut(option, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("option %q: want key=value", option)
		}
		if key != OptionKey {
			return nil, fmt.Errorf("unknown option %q (only %q is supported)", key, OptionKey)
		}
		opts[key] = value
	}
	if opts[OptionKey] == "" {
		return nil, errors.New("--option key=<path> is required")
	}
	return opts, nil
}
