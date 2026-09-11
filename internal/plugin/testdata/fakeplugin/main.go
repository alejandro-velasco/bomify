// Command fakeplugin is a synthetic bomify-build-* plugin used only by
// internal/plugin's tests, so Run can be exercised without depending on a
// real external tool.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type result struct {
	OutputPath string `json:"outputPath"`
	Message    string `json:"message,omitempty"`
}

func main() {
	componentJSON := flag.String("component", "", "JSON-encoded CycloneDX component")
	output := flag.String("output", "", "output directory")
	flag.Parse()

	var component cdx.Component
	if err := json.Unmarshal([]byte(*componentJSON), &component); err != nil {
		fmt.Fprintf(os.Stderr, "decode component: %v\n", err)
		os.Exit(1)
	}

	if component.Name == "fail-me" {
		fmt.Fprintln(os.Stderr, "simulated failure")
		os.Exit(1)
	}

	res := result{
		OutputPath: fmt.Sprintf("%s/%s-%s.tar", *output, component.Name, component.Version),
		Message:    "fake pull ok",
	}

	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(1)
	}
}
