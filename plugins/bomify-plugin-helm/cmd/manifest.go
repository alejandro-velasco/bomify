package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

// defaultManifestPath is "sbom generate"'s --manifest default: a file
// name it opportunistically reads if present in the working directory,
// with no error if it isn't there — unlike a path given explicitly via
// --manifest, which must exist.
const defaultManifestPath = "bomify-helm-sbom.yaml"

// manifest is the on-disk shape of "sbom generate"'s optional config
// file (see defaultManifestPath), mirroring its own flags key-for-key —
// see newSBOMGenerateCmd. Any flag given explicitly on the command line
// takes precedence over the same key here; see resolveString/resolveValues.
type manifest struct {
	Chart       string   `json:"chart,omitempty"`
	Repo        string   `json:"repo,omitempty"`
	Version     string   `json:"version,omitempty"`
	Values      []string `json:"values,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	ReleaseName string   `json:"release-name,omitempty"`
	KubeVersion string   `json:"kube-version,omitempty"`
	Output      string   `json:"output,omitempty"`
}

// loadManifest reads and parses the YAML manifest at path. A missing
// file is not an error unless explicit is true (i.e. --manifest named
// path directly, rather than path being its unchanged default) — a
// manifest is meant to be optional, so "sbom generate" without one must
// still work from flags alone.
func loadManifest(path string, explicit bool) (manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return manifest{}, nil
		}
		return manifest{}, fmt.Errorf("read manifest %s: %w", path, err)
	}

	var m manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return manifest{}, fmt.Errorf("parse manifest %s: %w", path, err)
	}

	return m, nil
}

// resolveString returns flagValue if flagName was explicitly passed on
// the command line, or manifestValue is empty; otherwise it returns
// manifestValue. This is how every "sbom generate" flag except --values
// combines with its manifest counterpart: an explicit flag always wins,
// an unset flag falls back to the manifest, and an absent manifest key
// falls back to whatever default (possibly empty) the flag itself
// already carries in flagValue.
func resolveString(cmd *cobra.Command, flagName, flagValue, manifestValue string) string {
	if cmd.Flags().Changed(flagName) || manifestValue == "" {
		return flagValue
	}
	return manifestValue
}

// resolveValues is resolveString's --values counterpart: a repeatable
// flag, so precedence is all-or-nothing per source rather than merged
// entry-by-entry — an explicit --values (one or more) replaces the
// manifest's "values" list entirely, it doesn't add to it.
func resolveValues(cmd *cobra.Command, flagValues, manifestValues []string) []string {
	if cmd.Flags().Changed("values") || len(manifestValues) == 0 {
		return flagValues
	}
	return manifestValues
}
