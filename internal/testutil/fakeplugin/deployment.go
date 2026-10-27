package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// repeated is a flag that may be given more than once.
type repeated []string

func (r *repeated) String() string { return strings.Join(*r, ",") }

func (r *repeated) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// generated is what deploymentMain records of what it was given, in
// "<output>/generated.json", for tests to check.
type generated struct {
	Name     string          `json:"name"`
	Package  json.RawMessage `json:"package"`
	Config   string          `json:"config,omitempty"`
	Overlays []string        `json:"overlays,omitempty"`
	Options  []string        `json:"options,omitempty"`
}

// deploymentMain implements the deployment contract: "deployment
// generate" writes generated.json and reports it. FAKEDEPLOY_FAIL fails
// the deployment of that name, and FAKEDEPLOY_UNREPORTED makes the one of
// that name write a file it doesn't report.
func deploymentMain() {
	if len(os.Args) < 3 || os.Args[2] != "generate" {
		fmt.Fprintln(os.Stderr, "usage: fakeplugin deployment generate --name <name> --package <path> --output <dir> ...")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	name := fs.String("name", "", "the deployment's name")
	packageFile := fs.String("package", "", "the package description")
	output := fs.String("output", "", "the directory to write into")
	config := fs.String("config", "", "the deployment's config")
	fs.String("log", "", "log file path")
	fs.Bool("log-color", false, "enable ANSI color codes in the log output")
	var overlays, options repeated
	fs.Var(&overlays, "overlay", "a file to lay over the config's output")
	fs.Var(&options, "option", "a key=value setting")
	fs.Parse(os.Args[3:])

	if *name == os.Getenv("FAKEDEPLOY_FAIL") {
		fmt.Fprintln(os.Stderr, "simulated deployment failure")
		os.Exit(1)
	}

	description, err := os.ReadFile(*packageFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read package description: %v\n", err)
		os.Exit(1)
	}
	record := generated{
		Name:     *name,
		Package:  description,
		Config:   *config,
		Overlays: overlays,
		Options:  options,
	}
	data, err := json.Marshal(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(*output, "generated.json"), data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	if *name == os.Getenv("FAKEDEPLOY_UNREPORTED") {
		if err := os.WriteFile(filepath.Join(*output, "unreported.txt"), nil, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf(`{"files":["generated.json"],"instructions":"apply %s"}`+"\n", *name)
}
