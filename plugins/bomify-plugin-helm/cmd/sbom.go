package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-helm/internal/chart"
)

// sbomCmd implements the SBOM generation plugin contract (see
// plugins/contracts/sbom/v1/CONTRACT.md), kept independent of this
// binary's component contract commands.
func sbomCmd() *cobra.Command {
	return plugin.SBOMCommand(sbomGenerator{}, plugin.SBOMHelp{
		Generate:      "Render the chart's templates and report the container images it references",
		Long:          generateLong,
		DefaultConfig: defaultConfigPath,
	})
}

const generateLong = `Generate fetches the given chart and renders its templates locally
via the Helm SDK (the same code path as "helm template"), then walks
the rendered manifests for Deployment/StatefulSet/DaemonSet/Job/
CronJob/Pod resources, collecting every container image their pod
specs reference from its known locations (containers, initContainers,
ephemeralContainers). Custom resources aren't inspected yet.

The result is printed as a CycloneDX SBOM (JSON) to stdout by default
(--output redirects it to a file instead), and nothing else is ever
written there; routine progress is logged to stderr.

The chart is described by --config, an options file, JSON or YAML.
Without --config, "bomify-helm-sbom.yaml" is read from the working
directory if present. Its keys, of which only chart and repo are
required:

  chart            chart name
  repo             chart repository: https://... or oci://...
  version          chart version; the latest if omitted
  values           values files merged into the chart's defaults, in
                   order, like repeated "helm template -f"
  namespace        .Release.Namespace; "default" if omitted
  release-name     .Release.Name; "release-name" if omitted
  kube-version     Kubernetes version to render for, e.g. 1.31.0

Rendering happens locally, without a Kubernetes cluster, so
.Capabilities.KubeVersion and a chart's own Chart.yaml "kubeVersion"
constraint are checked against a fixed default — the Kubernetes version
matching the client libraries this plugin was built with — unless
kube-version overrides it. Set it to the version you actually deploy
to, so templates render as they would there and a chart whose
"kubeVersion" constraint excludes that version fails with an
"incompatible with Kubernetes" error instead of rendering anyway.`

// sbomGenerator implements plugin.SBOMPlugin over internal/chart.
type sbomGenerator struct{}

func (sbomGenerator) Generate(_ context.Context, raw json.RawMessage, logger *slog.Logger) (*cdx.BOM, error) {
	var o options
	if err := plugin.DecodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if o.Chart == "" {
		return nil, errors.New(`required "chart" not set in the options`)
	}
	if o.Repo == "" {
		return nil, errors.New(`required "repo" not set in the options`)
	}

	return chart.Generate(chart.GenerateOptions{
		Name:          o.Chart,
		RepositoryURL: o.Repo,
		Version:       o.Version,
		ValuesFiles:   o.Values,
		Namespace:     o.Namespace,
		ReleaseName:   o.ReleaseName,
		KubeVersion:   o.KubeVersion,
	}, logger)
}
