// Command bomify-plugin-helm is bomify's plugin for Helm chart
// components. It implements the pull/push contract described in
// plugins/COMPONENT-CONTRACT.md, using the Helm SDK (helm.sh/helm/v4):
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
	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-helm/cmd"
)

func main() {
	plugin.Run(cmd.NewRootCmd())
}
