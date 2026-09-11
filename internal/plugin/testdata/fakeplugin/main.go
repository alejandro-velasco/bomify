// Command fakeplugin is a synthetic bomify-plugin-* plugin used only by
// internal/plugin's tests, so Pull and Push can be exercised without
// depending on a real external tool.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type hash struct {
	Algorithm cdx.HashAlgorithm `json:"algorithm,omitempty"`
	Value     string            `json:"value,omitempty"`
}

type result struct {
	OutputPath string `json:"outputPath"`
	Message    string `json:"message,omitempty"`
	Hash       hash   `json:"hash,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fakeplugin <pull|push> --component <json> ...")
		os.Exit(1)
	}

	verb := os.Args[1]
	fs := flag.NewFlagSet(verb, flag.ExitOnError)
	componentJSON := fs.String("component", "", "JSON-encoded CycloneDX component")
	output := fs.String("output", "", "output directory (pull)")
	input := fs.String("input", "", "input directory (push)")
	remote := fs.String("remote", "", "remote endpoint (push)")
	hashAlgorithm := fs.String("hash", "", "hash algorithm to report (pull)")
	fs.Parse(os.Args[2:])

	var component cdx.Component
	if err := json.Unmarshal([]byte(*componentJSON), &component); err != nil {
		fmt.Fprintf(os.Stderr, "decode component: %v\n", err)
		os.Exit(1)
	}

	if component.Name == "fail-me" {
		fmt.Fprintln(os.Stderr, "simulated failure")
		os.Exit(1)
	}

	var res result
	switch verb {
	case "pull":
		if info, err := os.Stat(*output); err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "expected --output %q to already exist as a directory: %v\n", *output, err)
			os.Exit(1)
		}

		res = result{
			OutputPath: fmt.Sprintf("%s/%s-%s.tar", *output, component.Name, component.Version),
			Message:    "fake pull ok",
		}

		// "nohash-*" components simulate a plugin that can't compute the
		// requested hash algorithm and leaves Hash unset.
		if *hashAlgorithm != "" && !strings.HasPrefix(component.Name, "nohash-") {
			res.Hash = hash{
				Algorithm: cdx.HashAlgorithm(*hashAlgorithm),
				Value:     fmt.Sprintf("fakehash-%s-%s", component.Name, component.Version),
			}
		}
	case "push":
		if info, err := os.Stat(*input); err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "expected --input %q to already exist as a directory: %v\n", *input, err)
			os.Exit(1)
		}

		res = result{
			OutputPath: fmt.Sprintf("%s/%s:%s", *remote, component.Name, component.Version),
			Message:    "fake push ok",
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown verb %q\n", verb)
		os.Exit(1)
	}

	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(1)
	}
}
