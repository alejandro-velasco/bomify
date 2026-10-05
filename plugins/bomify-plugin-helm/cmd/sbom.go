package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"

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
		Flags:         generateFlags,
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

Rendering happens locally, without a Kubernetes cluster, so
.Capabilities.KubeVersion and a chart's own Chart.yaml "kubeVersion"
constraint are checked against a fixed default — the Kubernetes version
matching the client libraries this plugin was built with — unless
--kube-version overrides it. Set it to the version you actually deploy
to, so templates render as they would there and a chart whose
"kubeVersion" constraint excludes that version fails with an
"incompatible with Kubernetes" error instead of rendering anyway.

Every flag can instead be set in an options file, JSON or YAML, with
the same keys. --config's
default, "bomify-helm-sbom.yaml", is read if present in the working
directory; a --config named explicitly must exist. A flag given
explicitly always takes precedence over the same key in the file. The
file can also have an "extraComponents" list of CycloneDX components,
appended to the SBOM as-is.`

// sbomGenerator implements plugin.SBOMPlugin over internal/chart.
type sbomGenerator struct{}

func (sbomGenerator) Generate(_ context.Context, raw json.RawMessage, logger *slog.Logger) (*cdx.BOM, error) {
	var o options
	if err := plugin.DecodeOptions(raw, &o); err != nil {
		return nil, err
	}
	if o.Chart == "" {
		return nil, errors.New(`required "chart" not set: pass --chart, or set it in --config`)
	}
	if o.Repo == "" {
		return nil, errors.New(`required "repo" not set: pass --repo, or set it in --config`)
	}

	bom, err := chart.Generate(chart.GenerateOptions{
		Name:          o.Chart,
		RepositoryURL: o.Repo,
		Version:       o.Version,
		ValuesFiles:   o.Values,
		Namespace:     o.Namespace,
		ReleaseName:   o.ReleaseName,
		KubeVersion:   o.KubeVersion,
	}, logger)
	if err != nil {
		return nil, err
	}

	addExtraComponents(bom, o.ExtraComponents)
	return bom, nil
}

// addExtraComponents appends extra to bom's components, each missing
// bom-ref set to its purl as the SBOM contract requires, with the chart
// depending on them as it does on its images.
func addExtraComponents(bom *cdx.BOM, extra []cdx.Component) {
	if len(extra) == 0 {
		return
	}
	components := deref(bom.Components)
	var refs []string
	for _, c := range extra {
		if c.BOMRef == "" {
			c.BOMRef = c.PackageURL
		}
		components = append(components, c)
		refs = append(refs, c.BOMRef)
	}
	bom.Components = &components

	if bom.Dependencies == nil || len(*bom.Dependencies) == 0 {
		return
	}
	chart := &(*bom.Dependencies)[0]
	on := append(slices.Clone(deref(chart.Dependencies)), refs...)
	chart.Dependencies = &on
}

func deref[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
