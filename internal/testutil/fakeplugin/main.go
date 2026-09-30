// Command fakeplugin is a synthetic bomify-plugin-* binary used only by
// tests, implementing every plugin contract bomify drives (see plugins/*
// -CONTRACT.md) without depending on a real tool: the component contract
// (component.go), the security scanning contract (security.go), the
// signing contract (signature.go), and SBOM generation (below). Install
// it with testutil.InstallFakePlugin. Each contract's behavior is driven
// by magic purls and environment variables, documented where they're
// read.
//
// It deliberately hand-rolls each contract rather than using pkg/plugin,
// so bomify's side is tested against the contracts themselves.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fakeplugin <component|security|signature|sbom> ...")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "component":
		componentMain()
	case "security":
		securityMain()
	case "signature":
		signatureMain()
	default:
		sbomMain()
	}
}

// sbomMain stands in for "sbom generate", whose arguments bomify passes
// through unparsed (see plugins/SBOM-CONTRACT.md): it echoes its own
// arguments to stdout and, if any is exactly "--fail", writes to stderr
// and exits 7 instead, so tests can check both paths and that the exit
// code propagates.
func sbomMain() {
	fmt.Fprintln(os.Stdout, strings.Join(os.Args[1:], " "))

	for _, arg := range os.Args[1:] {
		if arg == "--fail" {
			fmt.Fprintln(os.Stderr, "simulated failure")
			os.Exit(7)
		}
	}
}
