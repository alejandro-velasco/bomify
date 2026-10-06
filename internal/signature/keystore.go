package signature

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/namedstore"
	"github.com/alejandro-velasco/bomify/internal/rules"
)

// StoredKey is one public key (or certificate) in a data directory's
// managed key store (see AddKey), named so trust rules can refer to it
// (see Rule.KeyOptions).
type StoredKey = namedstore.Entry

func keyStore(baseDir string) namedstore.Store {
	return namedstore.Store{Dir: layout.Keys(baseDir), Ext: ".pem", Kind: "key"}
}

// ListKeys returns every key in baseDir's managed store, sorted by name.
func ListKeys(baseDir string) ([]StoredKey, error) {
	return keyStore(baseDir).List()
}

// AddKey copies the PEM file at path into baseDir's managed key store
// under name, replacing whatever name referred to before. Only public
// material is accepted — public keys and certificates, each of which
// must actually parse (see checkPublicPEM) — since trust rules only ever
// verify: a signing key is never copied into the data directory by
// mistake, and a corrupt or wrong file fails here rather than on some
// later pull. The copy is content-addressed, so later edits to path
// don't reach the store until it's added again.
func AddKey(baseDir, name, path string) (StoredKey, error) {
	store := keyStore(baseDir)
	if err := namedstore.ValidateName(store.Kind, name); err != nil {
		return StoredKey{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return StoredKey{}, fmt.Errorf("read %s: %w", path, err)
	}
	if err := checkPublicPEM(data); err != nil {
		return StoredKey{}, fmt.Errorf("%s: %w", path, err)
	}
	return store.Add(name, path, data)
}

// checkPublicPEM requires data to be PEM with at least one block, every
// one of them public material that parses: an X.509 certificate, a
// PKIX public key (RSA, ECDSA, Ed25519), or a PKCS#1 RSA public key.
// Anything else is refused — an allowlist, so an unfamiliar label fails
// closed, and a private key is caught even if mislabeled "PUBLIC KEY"
// (it won't parse as one).
func checkPublicPEM(data []byte) error {
	var blocks int
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++

		if strings.Contains(block.Type, "PRIVATE KEY") {
			return fmt.Errorf("block %d is a %q: only public keys and certificates can be stored; keep private keys out of the data directory and sign with --sign-option instead", blocks, block.Type)
		}

		var err error
		switch block.Type {
		case "CERTIFICATE":
			_, err = x509.ParseCertificate(block.Bytes)
		case "PUBLIC KEY":
			_, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			_, err = x509.ParsePKCS1PublicKey(block.Bytes)
		default:
			return fmt.Errorf("block %d is a %q: only CERTIFICATE, PUBLIC KEY, and RSA PUBLIC KEY blocks can be stored", blocks, block.Type)
		}
		if err != nil {
			return fmt.Errorf("block %d (%s) doesn't parse: %w", blocks, block.Type, err)
		}
	}
	if blocks == 0 {
		return fmt.Errorf("not a PEM file")
	}
	return nil
}

// RemoveKey removes name from baseDir's managed key store, deleting its
// stored copy unless another name still refers to the same content. It
// refuses while a trust rule refers to name, so no rule is left pointing
// at nothing.
func RemoveKey(baseDir, name string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}
	uses := func(r Rule) bool {
		for _, signer := range r.Signers {
			for _, keyName := range signer.KeyOptions {
				if keyName == name {
					return true
				}
			}
		}
		return false
	}
	if err := rules.Users(config, uses, ruleMatch, name, "key", "trust"); err != nil {
		return err
	}
	return keyStore(baseDir).Remove(name)
}

// keyOptionArgs turns keyOptions — plugin option name to stored key
// name — into "option=<path of the stored copy>" options, sorted by
// option name so the plugin sees them in a stable order.
func keyOptionArgs(baseDir string, keyOptions map[string]string) ([]string, error) {
	if len(keyOptions) == 0 {
		return nil, nil
	}
	options := make([]string, 0, len(keyOptions))
	for option := range keyOptions {
		options = append(options, option)
	}
	sort.Strings(options)

	names := make([]string, len(options))
	for i, option := range options {
		names[i] = keyOptions[option]
	}
	paths, err := keyStore(baseDir).Resolve(names)
	if err != nil {
		return nil, fmt.Errorf("%w (see \"bomify trust key add\")", err)
	}

	args := make([]string, len(options))
	for i, option := range options {
		args[i] = option + "=" + paths[i]
	}
	return args, nil
}

// ReadResolved is Read followed by ResolveKeyOptions: baseDir's trust
// rules, ready to verify with. It fails on a rule that doesn't validate
// (e.g. one edited by hand to have no signers), rather than verifying
// less than it asks for.
func ReadResolved(baseDir string) (Config, error) {
	config, err := Read(baseDir)
	if err != nil {
		return nil, err
	}
	for _, rule := range config {
		if err := rule.validate(); err != nil {
			return nil, fmt.Errorf("trust rule %q: %w", rules.Display(rule.Match), err)
		}
	}
	return ResolveKeyOptions(baseDir, config)
}

// ResolveKeyOptions returns rules with each signer's KeyOptions turned
// into plain Options pointing at the stored keys' copies in baseDir, so
// a verifying plugin gets file paths exactly as if they'd been given
// with --option. It fails on a key name missing from the store, naming
// the rule and signer.
func ResolveKeyOptions(baseDir string, config Config) (Config, error) {
	resolved := slices.Clone(config)
	for ruleIndex, rule := range resolved {
		signers := slices.Clone(rule.Signers)
		for signerIndex, signer := range signers {
			args, err := keyOptionArgs(baseDir, signer.KeyOptions)
			if err != nil {
				signerErr := &SignerError{
					Name: signer.Name,
					Err:  err,
				}
				return nil, fmt.Errorf("trust rule %q: %w", rules.Display(rule.Match), signerErr)
			}
			signers[signerIndex].Options = append(slices.Clone(signer.Options), args...)
			signers[signerIndex].KeyOptions = nil
		}
		resolved[ruleIndex].Signers = signers
	}
	return resolved, nil
}
