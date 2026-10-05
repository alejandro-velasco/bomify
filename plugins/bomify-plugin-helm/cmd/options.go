package cmd

import cdx "github.com/CycloneDX/cyclonedx-go"

// defaultConfigPath is "sbom generate"'s --config default: read if
// present in the working directory, skipped if not.
const defaultConfigPath = "bomify-helm-sbom.yaml"

// options is "sbom generate"'s options object, --config's keys (see
// generateLong).
type options struct {
	Chart       string   `json:"chart,omitempty"`
	Repo        string   `json:"repo,omitempty"`
	Version     string   `json:"version,omitempty"`
	Values      []string `json:"values,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	ReleaseName string   `json:"release-name,omitempty"`
	KubeVersion string   `json:"kube-version,omitempty"`
	// ExtraComponents are appended to the generated SBOM as-is, apart
	// from a missing bom-ref defaulting to the purl, for anything
	// Generate has no way to discover (e.g. an image no rendered pod
	// spec names).
	ExtraComponents []cdx.Component `json:"extraComponents,omitempty"`
}
