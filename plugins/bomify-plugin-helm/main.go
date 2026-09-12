// Command bomify-plugin-helm is bomify's plugin for Helm chart
// components. It implements the pull/push contract described in
// bomify/internal/plugin, using the Helm SDK (helm.sh/helm/v3):
//
//	bomify-plugin-helm pull --purl '<component purl>' --output <dir>
//	bomify-plugin-helm push --purl '<component purl>' --input <dir> --remote <endpoint>
//
// pull resolves a chart reference from the component's purl and downloads
// it, supporting both classic HTTP(S) chart repositories and OCI
// registries. push publishes the chart a prior pull wrote into --input to
// remote, and only supports OCI registries — the Helm SDK has no upload
// API for classic chart repositories.
package main

import (
	"fmt"
	"os"

	"bomify/plugins/bomify-plugin-helm/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
