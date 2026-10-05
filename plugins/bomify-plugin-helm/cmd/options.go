package cmd

import (
	"encoding/json"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/pflag"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// defaultConfigPath is "sbom generate"'s --config default: read if
// present in the working directory, skipped if not.
const defaultConfigPath = "bomify-helm-sbom.yaml"

// options is "sbom generate"'s options object: --config's keys, each
// also settable by the flag of the same name (see generateFlags).
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

// generateFlags adds "sbom generate"'s flags, one per options key but
// extraComponents, and returns how to apply them over --config's
// options: a flag given explicitly wins, and --values replaces the
// config's "values" outright rather than adding to it. "--manifest", the
// old name of --config, still works.
func generateFlags(flags *pflag.FlagSet) func(json.RawMessage) (json.RawMessage, error) {
	var f options
	flags.StringVar(&f.Chart, "chart", "", "chart name (required, unless set in --config)")
	flags.StringVar(&f.Repo, "repo", "", "chart repository URL, classic HTTP(S) or oci:// (required, unless set in --config)")
	flags.StringVar(&f.Version, "version", "", "chart version (defaults to the latest available)")
	flags.StringArrayVarP(&f.Values, "values", "f", nil, "values file to merge into the chart's defaults (repeatable)")
	flags.StringVar(&f.Namespace, "namespace", "default", "namespace templates are rendered as if installed into")
	flags.StringVar(&f.ReleaseName, "release-name", "release-name", "release name templates are rendered as if installed under")
	flags.StringVar(&f.KubeVersion, "kube-version", "", "Kubernetes version to render templates and check Chart.yaml's kubeVersion constraint against, e.g. 1.31.0 (defaults to the Helm SDK's own built-in default)")
	flags.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "manifest" {
			name = "config"
		}
		return pflag.NormalizedName(name)
	})

	return func(raw json.RawMessage) (json.RawMessage, error) {
		var o options
		if err := plugin.DecodeOptions(raw, &o); err != nil {
			return nil, err
		}
		for name, dst := range map[string]*string{
			"chart": &o.Chart, "repo": &o.Repo, "version": &o.Version, "namespace": &o.Namespace,
			"release-name": &o.ReleaseName, "kube-version": &o.KubeVersion,
		} {
			if flags.Changed(name) {
				*dst, _ = flags.GetString(name)
			}
		}
		if flags.Changed("values") {
			o.Values = f.Values
		}
		return json.Marshal(o)
	}
}
