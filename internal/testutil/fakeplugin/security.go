package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// securityMain implements the security scanning contract: "security
// <scan|supported-components>".
func securityMain() {
	if len(os.Args) < 3 {
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

// installedKind is the kind this copy is installed as: its executable's
// name, less "bomify-plugin-" and any ".exe".
func installedKind() string {
	name := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	return strings.TrimPrefix(name, "bomify-plugin-")
}

func usageError() {
	fmt.Fprintln(os.Stderr, "usage: fakeplugin security <scan --purl <purl>|supported-components>")
	os.Exit(1)
}

// supportedComponents prints the JSON object named by
// FAKESECURITY_SUPPORTED_COMPONENTS_<KIND> — <KIND> being the kind this
// copy is installed as, upper-cased (e.g. GRYPE for bomify-plugin-grype),
// so several copies can each support different types — else by
// FAKESECURITY_SUPPORTED_COMPONENTS, else a reasonable default
// (oci/helm/generic, sca) — so most tests don't need to set it at all,
// only ones exercising the capability filter itself.
// FAKESECURITY_SUPPORTED_COMPONENTS_FAIL simulates this subcommand
// itself failing (e.g. an out-of-date plugin that doesn't implement it).
func supportedComponents() {
	if os.Getenv("FAKESECURITY_SUPPORTED_COMPONENTS_FAIL") != "" {
		fmt.Fprintln(os.Stderr, "simulated supported-components failure")
		os.Exit(1)
	}

	resp := os.Getenv("FAKESECURITY_SUPPORTED_COMPONENTS_" + strings.ToUpper(installedKind()))
	if resp == "" {
		resp = os.Getenv("FAKESECURITY_SUPPORTED_COMPONENTS")
	}
	if resp == "" {
		resp = `{"types":["oci","helm","generic"],"scans":["sca"]}`
	}
	fmt.Println(resp)
}

// scan prints the SecurityResult object FAKESECURITY_RESPONSES_FILE maps
// --purl to (see writeResponsesFile), or "{}" (no vulnerabilities, no
// components) if that purl has no entry — or no responses file was
// given at all. Like a real plugin, whatever "affects" the canned
// response sets is printed verbatim: this fake never adds or rewrites
// it itself.
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
		result = json.RawMessage("{}")
	}

	fmt.Println(string(result))
}
