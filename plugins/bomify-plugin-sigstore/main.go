// Command bomify-plugin-sigstore is bomify's signing plugin backed by
// Sigstore (via sigstore-go), producing standard v0.3 Sigstore bundles.
// It implements the contract described in
// plugins/SIGNING-CONTRACT.md:
//
//	bomify-plugin-sigstore signature sign --payload <file> --reference <ref> [--option key=<private key>]
//	bomify-plugin-sigstore signature verify --payload <file> --envelope <file> --media-type <mt> --reference <ref> \
//	    (--option key=<public key> | --option certificate-identity=<id> --option certificate-oidc-issuer=<issuer>)
//	bomify-plugin-sigstore signature supported-types
//
// With a key option, it signs with a local private key (a Sigstore-format
// or PKCS#8 encrypted key, decrypted with SIGSTORE_PASSWORD, or a plain
// PEM key) and verifies against the matching public key, entirely
// offline. Without one, it signs keyless: a short-lived Fulcio
// certificate for the OIDC identity token in SIGSTORE_ID_TOKEN (e.g. a CI
// workflow's own), logged in Rekor, and verifies against the public-good
// Sigstore trusted root, requiring the certificate identity and issuer
// given.
package main

import (
	"fmt"
	"os"

	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-sigstore/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
