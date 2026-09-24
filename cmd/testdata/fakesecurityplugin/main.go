// Command fakesecurityplugin is a synthetic bomify-plugin-* used only by
// cmd's tests, to exercise "bomify security scan"'s per-component
// dispatch, capability filtering, and merge logic without depending on
// a real plugin.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "security" {
		usageError()
	}

	switch os.Args[2] {
	case "supported-components":
		supportedComponents()
	case "scan":
		scan()
	default:
		usageError()
	}
}

func usageError() {
	fmt.Fprintln(os.Stderr, "usage: fakesecurityplugin security <scan --purl <purl>|supported-components>")
	os.Exit(1)
}

// supportedComponents prints the JSON object named by
// FAKESECURITY_SUPPORTED_COMPONENTS, or a reasonable default
// (oci/helm/generic, sca) if that's unset — so most tests don't need to
// set it at all, only ones exercising the capability filter itself.
// FAKESECURITY_SUPPORTED_COMPONENTS_FAIL simulates this subcommand
// itself failing (e.g. an out-of-date plugin that doesn't implement it).
func supportedComponents() {
	if os.Getenv("FAKESECURITY_SUPPORTED_COMPONENTS_FAIL") != "" {
		fmt.Fprintln(os.Stderr, "simulated supported-components failure")
		os.Exit(1)
	}

	resp := os.Getenv("FAKESECURITY_SUPPORTED_COMPONENTS")
	if resp == "" {
		resp = `{"types":["oci","helm","generic"],"scans":["sca"]}`
	}
	fmt.Println(resp)
}

// scan prints the vulnerability array FAKESECURITY_RESPONSES_FILE maps
// --purl to (see writeResponsesFile), or "[]" if that purl has no entry
// — or no responses file was given at all.
func scan() {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	purl := fs.String("purl", "", "component purl")
	fs.Parse(os.Args[3:])

	// A magic purl tests use to simulate a scan failure, since it's
	// otherwise never one a real component would carry.
	if *purl == "pkg:generic/fail-me@1.0" {
		fmt.Fprintln(os.Stderr, "simulated failure")
		os.Exit(1)
	}

	responses := map[string]json.RawMessage{}
	if path := os.Getenv("FAKESECURITY_RESPONSES_FILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &responses)
		}
	}

	result, ok := responses[*purl]
	if !ok {
		result = json.RawMessage("[]")
	}

	fmt.Println(string(result))
}
