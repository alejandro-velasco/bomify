// Command bomify-plugin-grype is bomify's security scanning plugin
// backed by Anchore's grype vulnerability scanner. It implements the
// contract described in plugins/SECURITY-CONTRACT.md:
//
//	bomify-plugin-grype security scan --purl '<component purl>'
//	bomify-plugin-grype security supported-components
//
// security scan resolves the given purl to one or more packages via
// grype's own SDK (github.com/anchore/grype/grype/pkg.Provide) and
// matches them against grype's vulnerability database, printing the
// result as a JSON object of CycloneDX vulnerabilities (each one's
// "affects" set to whatever it's actually about — see below) and,
// where applicable, nested components. Most purl types name a specific
// package directly, so no cataloging — and no syft — is involved; each
// vulnerability's "affects" references that same purl back. An
// "oci"/"docker" purl names a whole container image instead, so those
// two are cataloged with syft first (still via grype's own SDK, its
// syft-backed provider) to find what's inside: every package found is
// reported as a nested component, and each vulnerability's "affects"
// references the specific package(s) actually affected, never the image
// itself. security supported-components reports the purl types grype
// has a dedicated matcher for, plus "oci"/"docker".
package main

import (
	"fmt"
	"os"

	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-grype/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
