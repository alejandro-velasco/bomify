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
	"strings"
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
	default:
		sbomMain()
	}
}

// sbomSchema is what "sbom schema" prints: options with one key, "bom",
// the SBOM "sbom generate --config" prints back.
const sbomSchema = `{"type":"object","additionalProperties":false,"required":["bom"],"properties":{"bom":{"type":"object"}}}`

// sbomMain stands in for the SBOM generation contract (see
// plugins/contracts/sbom/v1/CONTRACT.md). "sbom schema" prints sbomSchema,
// and "sbom generate --config <file>" prints the file's "bom" verbatim,
// so a test decides the SBOM, conforming or not; each such generate
// appends its working directory to FAKESBOM_LOG, if set. Any other
// arguments, which "bomify sbom generate" passes through unparsed, are
// echoed to stdout, unless one is exactly "--fail": then it writes to
// stderr and exits 7 instead, so tests can check that the exit code
// propagates.
func sbomMain() {
	if len(os.Args) == 3 && os.Args[2] == "schema" {
		fmt.Print(sbomSchema)
		return
	}
	if len(os.Args) == 5 && os.Args[2] == "generate" && os.Args[3] == "--config" {
		sbomGenerate(os.Args[4])
		return
	}

	fmt.Fprintln(os.Stdout, strings.Join(os.Args[1:], " "))

	for _, arg := range os.Args[1:] {
		if arg == "--fail" {
			fmt.Fprintln(os.Stderr, "simulated failure")
			os.Exit(7)
		}
	}
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
