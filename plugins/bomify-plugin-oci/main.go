// Command bomify-plugin-oci is bomify's plugin for container/OCI image
// components. It implements the pull/push contract described in
// github.com/alejandro-velasco/bomify/internal/plugin, using crane
// (github.com/google/go-containerregistry/pkg/crane) to talk to registries:
//
//	bomify-plugin-oci pull --component '<JSON-encoded CycloneDX component>' --output <dir>
//	bomify-plugin-oci push --component '<JSON-encoded CycloneDX component>' --remote <endpoint>
package main

import (
	"fmt"
	"os"

	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-oci/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
