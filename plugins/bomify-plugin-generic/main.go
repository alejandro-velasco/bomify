// Command bomify-plugin-generic is bomify's plugin for plain HTTP
// artifacts — anything reachable by a simple GET that doesn't fit a more
// specific plugin. It implements the component contract described in
// plugins/contracts/component/v1/CONTRACT.md:
//
//	bomify-plugin-generic component pull --purl '<component purl>' --output <dir>
//
// pull resolves the component's purl "download_url" qualifier
// (pkg:generic/<name>@<version>?download_url=<url>, per the package-url
// spec's "generic" type) and downloads it with an HTTP GET.
package main

import (
	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-generic/cmd"
)

func main() {
	plugin.Run(cmd.NewRootCmd())
}
