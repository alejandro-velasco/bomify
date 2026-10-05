// Command fakeplugin is a synthetic bomify-plugin-* binary used only by
// tests, implementing every plugin contract bomify drives (see
// plugins/contracts/) without depending on a real tool: the component contract
// (component.go), the security scanning contract (security.go), the
// signing contract (signature.go), SBOM generation (below), and the
// "contract" subcommand reporting their versions (contract.go). Install
// it with testutil.InstallFakePlugin. Each contract's behavior is driven
// by magic purls and environment variables, documented where they're
// read.
//
// It deliberately hand-rolls each contract rather than using pkg/plugin,
// so bomify's side is tested against the contracts themselves.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fakeplugin <component|security|signature|contract|sbom> ...")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "component":
		componentMain()
	case "security":
		securityMain()
	case "signature":
		signatureMain()
	case "contract":
		contractMain()
	case "sbom":
		sbomMain()
	default:
		fmt.Fprintln(os.Stderr, "usage: fakeplugin <component|security|signature|contract|sbom> ...")
		os.Exit(1)
	}
}

// sbomMain stands in for the SBOM generation contract (see
// plugins/contracts/sbom/v1/CONTRACT.md): "sbom generate --config <file>"
// prints the file's "bom" verbatim, so a test decides the SBOM,
// conforming or not; each generate appends its working directory to
// FAKESBOM_LOG, if set.
func sbomMain() {
	if len(os.Args) != 5 || os.Args[2] != "generate" || os.Args[3] != "--config" {
		fmt.Fprintln(os.Stderr, "usage: fakeplugin sbom generate --config <file>")
		os.Exit(1)
	}
	sbomGenerate(os.Args[4])
}

// sbomGenerate prints the "bom" of the options file at config.
func sbomGenerate(config string) {
	if logPath := os.Getenv("FAKESBOM_LOG"); logPath != "" {
		wd, _ := os.Getwd()
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintln(f, wd)
			f.Close()
		}
	}

	var options struct {
		BOM json.RawMessage `json:"bom"`
	}
	data, err := os.ReadFile(config)
	if err == nil {
		err = json.Unmarshal(data, &options)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "read options:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "generating")
	fmt.Println(string(options.BOM))
}
