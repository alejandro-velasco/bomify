// Command bomify-plugin-oci is bomify's plugin for container/OCI image
// components. It implements the component contract described in
// plugins/contracts/component/v1/CONTRACT.md, using crane
// (github.com/google/go-containerregistry/pkg/crane) to talk to registries:
//
//	bomify-plugin-oci component pull --purl '<component purl>' --output <dir>
package main

import (
	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-oci/cmd"
)

func main() {
	plugin.Run(cmd.NewRootCmd())
}
