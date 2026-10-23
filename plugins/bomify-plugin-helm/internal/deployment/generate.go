// Package deployment generates a Helm deployment of a package's chart
// (see plugins/contracts/deployment/v1/CONTRACT.md): its values, rendered
// from Go templates of the package's components, and how to install it.
package deployment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/package-url/packageurl-go"
	"sigs.k8s.io/yaml"

	"github.com/alejandro-velasco/bomify/pkg/plugin"
)

// ValuesFile is the values file Generate writes.
const ValuesFile = "values.yaml"

// The options a helm deployment takes.
const (
	// OptionChart selects the chart, among the package's charts, as
	// plugin.MatchesSelector does. It may be left out of a package with one
	// chart.
	OptionChart = "chart"
	// OptionRelease names the Helm release; the deployment's name by
	// default.
	OptionRelease = "release"
)

// Generate writes req's values into req.Output, rendered from req.Config
// and each of req.Overlays in turn, merged as "helm --values" merges
// values files, and reports how to install the chart with them.
func Generate(req plugin.GenerateRequest) (*plugin.DeploymentResult, error) {
	for key := range req.Options {
		if key != OptionChart && key != OptionRelease {
			return nil, fmt.Errorf("unknown option %q: a helm deployment takes %q and %q", key, OptionChart, OptionRelease)
		}
	}
	chart, err := selectChart(req.Package.Components, req.Options[OptionChart])
	if err != nil {
		return nil, err
	}
	release := req.Options[OptionRelease]
	if release == "" {
		release = req.Name
	}
	req.Logger.Info("generating", "release", release, "chart", chart.Purl)

	templates := req.Overlays
	if req.Config != "" {
		templates = append([]string{req.Config}, req.Overlays...)
	}
	values := map[string]any{}
	for _, path := range templates {
		rendered, err := render(path, req.Package, req.Logger)
		if err != nil {
			return nil, err
		}
		values = merge(values, rendered)
	}

	data, err := yaml.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("encode values: %w", err)
	}
	if err := os.WriteFile(filepath.Join(req.Output, ValuesFile), data, 0o644); err != nil {
		return nil, fmt.Errorf("write values: %w", err)
	}

	instructions := fmt.Sprintf("helm upgrade --install %s %s --values %s", release, chartReference(chart), ValuesFile)
	result := plugin.DeploymentResult{
		Files:        []string{ValuesFile},
		Instructions: instructions,
	}
	return &result, nil
}

// isChart reports whether component is a Helm chart: of purl type helm.
func isChart(component plugin.DeploymentComponent) bool {
	purl, err := packageurl.FromString(component.Purl)
	return err == nil && purl.Type == packageurl.TypeHelm
}

// selectChart returns the chart of components selector names (see
// plugin.MatchesSelector), or, if selector is empty, the only one.
func selectChart(components []plugin.DeploymentComponent, selector string) (plugin.DeploymentComponent, error) {
	charts := slices.DeleteFunc(slices.Clone(components), func(c plugin.DeploymentComponent) bool { return !isChart(c) })
	if selector != "" {
		chart, err := plugin.SelectComponent(charts, selector)
		if err != nil {
			return plugin.DeploymentComponent{}, fmt.Errorf("option %s: %w", OptionChart, err)
		}
		return chart, nil
	}
	if len(charts) == 1 {
		return charts[0], nil
	}
	names := make([]string, 0, len(charts))
	for _, chart := range charts {
		names = append(names, chart.Name)
	}
	if len(names) == 0 {
		return plugin.DeploymentComponent{}, fmt.Errorf("the package has no Helm chart")
	}
	return plugin.DeploymentComponent{}, fmt.Errorf("the package has several charts (%s): choose one with option %s", strings.Join(names, ", "), OptionChart)
}

// chartReference is where Helm installs chart from, pinned by digest: its
// own repository, if it's tagged in one, else the package's.
func chartReference(chart plugin.DeploymentComponent) string {
	if chart.Tagged != nil {
		return "oci://" + chart.Tagged.Registry + "/" + chart.Tagged.Repository + "@" + chart.Digest
	}
	return "oci://" + chart.Reference
}

// render renders the Go template at path with pkg, failing on a missing
// key rather than rendering it empty, and parses the result as values.
// A template is given the package as .Package, and a "component" function
// looking one up as plugin.SelectComponent does; both as the description's
// JSON has them, so their fields are as the contract names them.
func render(path string, pkg plugin.DeploymentPackage, logger *slog.Logger) (map[string]any, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}
	description, err := asMap(pkg)
	if err != nil {
		return nil, err
	}
	functions := sprig.TxtFuncMap()
	functions["toYaml"] = toYaml
	functions["component"] = func(selector string) (map[string]any, error) {
		component, err := plugin.SelectComponent(pkg.Components, selector)
		if err != nil {
			return nil, err
		}
		return asMap(component)
	}
	tmpl, err := template.New(filepath.Base(path)).Funcs(functions).Option("missingkey=error").Parse(string(source))
	if err != nil {
		return nil, fmt.Errorf("parse template %s: %w", path, err)
	}
	var out bytes.Buffer
	data := map[string]any{"Package": description}
	if err := tmpl.Execute(&out, data); err != nil {
		return nil, fmt.Errorf("render template %s: %w", path, err)
	}
	logger.Info("rendered", "template", path)

	values := map[string]any{}
	if err := yaml.Unmarshal(out.Bytes(), &values); err != nil {
		return nil, fmt.Errorf("template %s didn't render YAML values: %w", path, err)
	}
	return values, nil
}

// asMap is v as JSON decodes it into a map: with the fields its JSON
// names, so a template sees what the contract describes.
func asMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// toYaml is v as YAML, without a trailing newline, as Helm's own toYaml.
func toYaml(v any) (string, error) {
	data, err := yaml.Marshal(v)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}

// merge lays over on base as "helm --values" merges values files: maps key
// by key, anything else, a list among them, replaced whole. A null is
// kept, and so removes the key when Helm installs the chart.
func merge(base, over map[string]any) map[string]any {
	for key, value := range over {
		overMap, overIsMap := value.(map[string]any)
		baseMap, baseIsMap := base[key].(map[string]any)
		if overIsMap && baseIsMap {
			base[key] = merge(baseMap, overMap)
			continue
		}
		base[key] = value
	}
	return base
}
