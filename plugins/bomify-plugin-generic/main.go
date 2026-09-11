// Command bomify-plugin-generic is bomify's plugin for plain HTTP
// artifacts — anything reachable by a simple GET/PUT that doesn't fit a
// more specific plugin. It implements the pull/push contract described in
// github.com/alejandro-velasco/bomify/internal/plugin:
//
//	bomify-plugin-generic pull --purl '<component purl>' --output <dir>
//	bomify-plugin-generic push --purl '<component purl>' --input <dir> --remote <endpoint>
//
// pull resolves the component's purl "download_url" qualifier
// (pkg:generic/<name>@<version>?download_url=<url>, per the package-url
// spec's "generic" type) and downloads it with an HTTP GET. push uploads
// the file a prior pull wrote into --input to --remote with an HTTP PUT,
// using remote exactly as given (e.g. a presigned upload URL).
package main

import (
	"fmt"
	"os"

	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
