package main

import (
	"fmt"
	"os"
)

// allContracts is what contractMain reports by default: version 1 of
// every contract fakeplugin implements.
const allContracts = `{"component":1,"sbom":1,"security":1,"signing":1}`

// contractMain stands in for the "contract" subcommand every plugin
// answers (see plugins/README.md#contract-versions), reporting
// allContracts. Tests change that with FAKEPLUGIN_CONTRACTS: a JSON
// object to report instead, or "unsupported" to fail the way a plugin
// built before contract versions does.
func contractMain() {
	// Tests that need to count how often bomify asks point this at a log
	// file; every invocation appends a line to it.
	if logPath := os.Getenv("FAKEPLUGIN_CONTRACT_LOG"); logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			f.WriteString("contract\n")
			f.Close()
		}
	}

	contracts := os.Getenv("FAKEPLUGIN_CONTRACTS")
	switch contracts {
	case "":
		contracts = allContracts
	case "unsupported":
		fmt.Fprintln(os.Stderr, `unknown command "contract" for "bomify-plugin-fake"`)
		os.Exit(1)
	}
	fmt.Printf("{\"contracts\":%s}\n", contracts)
}
