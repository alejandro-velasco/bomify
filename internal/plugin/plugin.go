// Package plugin dispatches SBOM components to external "bomify-plugin-*"
// helper binaries, letting bomify delegate component types it doesn't know
// how to build itself (e.g. container images) to a separate executable.
//
// A plugin for "kind" must be named "bomify-plugin-<kind>", be discoverable
// on PATH, and implement two subcommands:
//
//	bomify-plugin-<kind> pull --component '<JSON-encoded CycloneDX component>' --output <dir>
//	bomify-plugin-<kind> push --component '<JSON-encoded CycloneDX component>' --remote <endpoint>
//
// pull fetches or builds the component and writes it into the local
// directory dir. push publishes an already-pulled component to the remote
// endpoint.
//
// On success the plugin must print a single JSON object describing the
// result to stdout (see Result) and exit 0. On failure it should exit
// non-zero; anything written to stderr is surfaced in bomify's error.
package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// binaryPrefix precedes the kind in a plugin's executable name.
const binaryPrefix = "bomify-plugin-"

// Result is the structured output a plugin prints to stdout on success.
type Result struct {
	// OutputPath is the location of the artifact the plugin produced.
	OutputPath string `json:"outputPath"`
	// Message is an optional human-readable summary of what happened.
	Message string `json:"message,omitempty"`
}

// Print writes r to w as the single JSON object bomify expects a plugin to
// print to stdout on success. Plugins should call this instead of
// re-implementing JSON encoding themselves.
func (r *Result) Print(w io.Writer) error {
	if err := json.NewEncoder(w).Encode(r); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}

// DecodeComponent unmarshals the JSON-encoded CycloneDX component a plugin
// receives via its --component flag.
func DecodeComponent(componentJSON string) (cdx.Component, error) {
	var component cdx.Component
	if err := json.Unmarshal([]byte(componentJSON), &component); err != nil {
		return cdx.Component{}, fmt.Errorf("decode component: %w", err)
	}
	return component, nil
}

// Detect returns the plugin kind corresponding to the given SBOM component.
func Detect(component cdx.Component) (string, error) {
	purl, err := packageurl.FromString(component.PackageURL)
	if err != nil {
		return "", fmt.Errorf("parse package URL: %w", err)
	}

	return purl.Type, nil
}

// BinaryName returns the expected executable name for the plugin handling
// kind, e.g. BinaryName("docker") == "bomify-plugin-docker".
func BinaryName(kind string) string {
	return binaryPrefix + kind
}

// Find resolves the plugin binary for kind by searching PATH. It returns an
// error if no such plugin is installed.
func Find(kind string) (string, error) {
	name := BinaryName(kind)

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("plugin %q not found on PATH: %w", name, err)
	}

	return path, nil
}

// Pull invokes the plugin binary's "pull" subcommand, which fetches or
// builds component and writes it into outputDir.
func Pull(path string, component cdx.Component, outputDir string) (*Result, error) {
	return run(path, "pull", component, "--output", outputDir)
}

// Push invokes the plugin binary's "push" subcommand, which publishes an
// already-pulled component to remote.
func Push(path string, component cdx.Component, remote string) (*Result, error) {
	return run(path, "push", component, "--remote", remote)
}

// run invokes the plugin binary at path with subcommand verb, passing
// component and the given extra flag/value pair as arguments, and returns
// the plugin's parsed result.
func run(path, verb string, component cdx.Component, extraFlag, extraValue string) (*Result, error) {
	componentJSON, err := json.Marshal(component)
	if err != nil {
		return nil, fmt.Errorf("marshal component: %w", err)
	}

	cmd := exec.Command(path, verb, "--component", string(componentJSON), extraFlag, extraValue)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run plugin %s %s: %w%s", path, verb, err, formatStderr(stderr.String()))
	}

	var result Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse output of plugin %s %s: %w", path, verb, err)
	}

	return &result, nil
}

func formatStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	return ": " + stderr
}
