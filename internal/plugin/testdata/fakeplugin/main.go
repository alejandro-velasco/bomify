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
	"github.com/package-url/packageurl-go"
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
		fmt.Fprintln(os.Stderr, "usage: fakeplugin <pull|push> --purl <purl> ...")
		os.Exit(1)
	}

	verb := os.Args[1]
	fs := flag.NewFlagSet(verb, flag.ExitOnError)
	purl := fs.String("purl", "", "component purl")
	output := fs.String("output", "", "output directory (pull)")
	input := fs.String("input", "", "input directory (push)")
	remote := fs.String("remote", "", "remote endpoint (push)")
	hashAlgorithm := fs.String("hash", "", "hash algorithm to report (pull)")
	fs.Parse(os.Args[2:])

	// "fail-me" is a magic purl value tests use to simulate a plugin
	// failure, since it's never a real, parseable purl.
	if *purl == "fail-me" {
		fmt.Fprintln(os.Stderr, "simulated failure")
		os.Exit(1)
	}

	name, version := nameVersion(*purl)

	var res result
	switch verb {
	case "pull":
		if info, err := os.Stat(*output); err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "expected --output %q to already exist as a directory: %v\n", *output, err)
			os.Exit(1)
		}

		res = result{
			OutputPath: fmt.Sprintf("%s/%s-%s.tar", *output, name, version),
			Message:    "fake pull ok",
		}

		// "nohash-*" purls simulate a plugin that can't compute the
		// requested hash algorithm and leaves Hash unset.
		if *hashAlgorithm != "" && !strings.HasPrefix(*purl, "nohash-") {
			res.Hash = hash{
				Algorithm: cdx.HashAlgorithm(*hashAlgorithm),
				Value:     fmt.Sprintf("fakehash-%s-%s", name, version),
			}
		}
	case "push":
		if info, err := os.Stat(*input); err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "expected --input %q to already exist as a directory: %v\n", *input, err)
			os.Exit(1)
		}

		res = result{
			OutputPath: fmt.Sprintf("%s/%s:%s", *remote, name, version),
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

// nameVersion extracts a name and version from purlString, falling back to
// treating the whole string as the name when it isn't a real purl (as with
// the synthetic "nohash-*" values tests use).
func nameVersion(purlString string) (name, version string) {
	p, err := packageurl.FromString(purlString)
	if err != nil {
		return purlString, "unknown"
	}
	return p.Name, p.Version
}
