package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/alejandro-velasco/bomify/internal/sbom"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// SBOMSchema returns the JSON Schema of the options the SBOM generation
// plugin at path takes, from its "sbom schema" (see
// plugins/contracts/sbom/v1/CONTRACT.md).
func SBOMSchema(path string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command(path, pluginlib.SBOMSubcommand, "schema")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run plugin %s sbom schema: %w%s", path, err, formatStderr(stderr.String()))
	}
	return out, nil
}

// ValidateOptions checks options, a JSON object, against schema, the
// JSON Schema a plugin's "sbom schema" printed.
func ValidateOptions(schema, options []byte) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return fmt.Errorf("parse the plugin's options schema: %w", err)
	}
	const url = "bomify:///options.schema.json"
	c := jsonschema.NewCompiler()
	if err := c.AddResource(url, doc); err != nil {
		return fmt.Errorf("load the plugin's options schema: %w", err)
	}
	compiled, err := c.Compile(url)
	if err != nil {
		return fmt.Errorf("compile the plugin's options schema: %w", err)
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(options))
	if err != nil {
		return fmt.Errorf("parse options: %w", err)
	}
	if err := compiled.Validate(inst); err != nil {
		// The first line only names the schema's internal URL; the rest
		// lists each violation, e.g. "- at '/chart': got number, want
		// string".
		_, violations, _ := strings.Cut(err.Error(), "\n")
		return errors.New(strings.ReplaceAll(strings.TrimPrefix(violations, "- "), "\n- ", "; "))
	}
	return nil
}

// GenerateSBOM runs the SBOM generation plugin at path unattended, "sbom
// generate --config configFile" in dir with stdin closed, and returns the
// SBOM it printed, checked against the contract's output rules (see
// pluginlib.ValidateGenerated). The plugin's stderr, its logs, goes to
// logs as it runs; its last line also ends the error if it fails.
func GenerateSBOM(path, configFile, dir string, logs io.Writer) (*cdx.BOM, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(path, pluginlib.SBOMSubcommand, "generate", "--config", configFile)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = io.MultiWriter(logs, &stderr)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run plugin %s sbom generate: %w%s", path, err, formatStderr(lastLine(stderr.String())))
	}

	bom, err := sbom.LoadBytes(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse the SBOM plugin %s printed: %w", path, err)
	}
	if err := pluginlib.ValidateGenerated(bom); err != nil {
		return nil, fmt.Errorf("the SBOM plugin %s printed breaks the SBOM contract: %w", path, err)
	}
	return bom, nil
}

// lastLine returns s's last non-blank line.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
