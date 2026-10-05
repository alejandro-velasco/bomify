package plugin

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/sbom"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// GenerateSBOM runs the SBOM generation plugin at path unattended, "sbom
// generate --config configFile" in dir with stdin closed (see
// plugins/contracts/sbom/v1/CONTRACT.md), and returns the SBOM it
// printed: decoded strictly (see sbom.DecodeStrict) and checked against
// the contract's output rules (see pluginlib.ValidateGenerated). The
// plugin's stderr, its logs, goes to logs as it runs; its last line also
// ends the error if it fails.
func GenerateSBOM(path, configFile, dir string, logs io.Writer) (*cdx.BOM, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(path, pluginlib.SBOMSubcommand, "generate", "--config", configFile)
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = io.MultiWriter(logs, &stderr)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run plugin %s sbom generate: %w%s", path, err, formatStderr(lastLine(stderr.String())))
	}

	bom, err := sbom.DecodeStrict(stdout.Bytes())
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
