// Package plugin dispatches SBOM components to external "bomify-build-*"
// helper binaries, letting bomify delegate component types it doesn't know
// how to build itself (e.g. container images) to a separate executable.
//
// A plugin for "kind" must be named "bomify-build-<kind>" and discoverable
// on PATH. bomify invokes it as:
//
//	bomify-build-<kind> --component '<JSON-encoded CycloneDX component>' --output <output-dir>
//
// On success the plugin must print a single JSON object describing the
// result to stdout (see Result) and exit 0. On failure it should exit
// non-zero; anything written to stderr is surfaced in bomify's error.
package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// binaryPrefix precedes the kind in a plugin's executable name.
const binaryPrefix = "bomify-build-"

// Result is the structured output a plugin prints to stdout on success.
type Result struct {
	// OutputPath is the location of the artifact the plugin produced.
	OutputPath string `json:"outputPath"`
	// Message is an optional human-readable summary of what happened.
	Message string `json:"message,omitempty"`
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
// kind, e.g. BinaryName("docker") == "bomify-build-docker".
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

// Run executes the plugin binary at path, passing component and outputDir
// as arguments, and returns the plugin's parsed result.
func Run(path string, component cdx.Component, outputDir string) (*Result, error) {
	componentJSON, err := json.Marshal(component)
	if err != nil {
		return nil, fmt.Errorf("marshal component: %w", err)
	}

	cmd := exec.Command(path, "--component", string(componentJSON), "--output", outputDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run plugin %s: %w%s", path, err, formatStderr(stderr.String()))
	}

	var result Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse output of plugin %s: %w", path, err)
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
