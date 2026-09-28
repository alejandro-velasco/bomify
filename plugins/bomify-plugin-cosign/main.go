// Command bomify-plugin-cosign is bomify's signing plugin backed by
// Sigstore (via sigstore-go), producing the same v0.3 Sigstore bundles
// cosign does. It implements the contract described in
// plugins/SIGNING-CONTRACT.md:
//
//	bomify-plugin-cosign signature sign --payload <file> --reference <ref> [--option k=v]...
//	bomify-plugin-cosign signature verify --payload <file> --envelope <file> --media-type <mt> --reference <ref> [--option k=v]...
//	bomify-plugin-cosign signature supported-types
//
// With --option key=<path>, it signs with a local private key (any key
// `cosign generate-key-pair` produces, decrypted with COSIGN_PASSWORD)
// and verifies against the matching public key, entirely offline.
// Without one, it signs keylessly — a Fulcio certificate for the OIDC
// identity in SIGSTORE_ID_TOKEN, logged to Rekor — and verifies against
// the public-good Sigstore trusted root, requiring the
// certificate-identity and certificate-oidc-issuer options (or their
// -regexp variants).
package main

import (
	"fmt"
	"os"

	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-cosign/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
