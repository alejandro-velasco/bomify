// Command bomify-plugin-huggingface is bomify's plugin for Hugging Face
// Hub models. It implements the component and SBOM generation contracts
// described in plugins/contracts/component/v1/CONTRACT.md and
// plugins/contracts/sbom/v1/CONTRACT.md:
//
//	bomify-plugin-huggingface component pull --purl '<component purl>' --output <dir>
//	bomify-plugin-huggingface component push --purl '<component purl>' --input <dir> --remote <hub>/<namespace>
//	bomify-plugin-huggingface sbom generate --config <options file>
//
// It handles pkg:huggingface/<namespace>/<name>@<commit>, the package-url
// spec's type for Hub models, pulling and pushing whole repositories over
// the Hub's HTTP API.
package main

import (
	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-huggingface/cmd"
)

func main() {
	plugin.Run(cmd.NewRootCmd())
}
