package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/plugins/bomify-plugin-helm/internal/chart"
)

// sbomCmd groups the SBOM generation plugin contract's "generate"
// subcommand (see plugins/SBOM-CONTRACT.md), kept independent of this
// binary's own component plugin subcommands under componentCmd.
func sbomCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "SBOM generation subcommands — see plugins/SBOM-CONTRACT.md",
	}

	cmd.AddCommand(newSBOMGenerateCmd())

	return cmd
}

func newSBOMGenerateCmd() *cobra.Command {
	var (
		chartName    string
		repo         string
		version      string
		valuesFiles  []string
		namespace    string
		releaseName  string
		kubeVersion  string
		outputPath   string
		manifestPath string
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Render the chart's templates and report the container images it references",
		Long: `Generate fetches the given chart and renders its templates locally
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
constraint are checked against a fixed, and rather old, default unless
--kube-version overrides it — a chart requiring a recent Kubernetes
version will otherwise fail to render with an "incompatible with
Kubernetes" error.

Every flag above can instead be set in a YAML manifest — --manifest's
default, "bomify-helm-sbom.yaml", is read if present in the working
directory (silently skipped if it isn't); a --manifest named explicitly
must exist. A flag given explicitly on the command line always takes
precedence over the same key in the manifest. The manifest can also
have an "extraComponents" list of CycloneDX components, appended to the
generated SBOM as-is.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

			m, err := loadManifest(manifestPath, cmd.Flags().Changed("manifest"))
			if err != nil {
				return err
			}

			opts := chart.GenerateOptions{
				Name:          resolveString(cmd, "chart", chartName, m.Chart),
				RepositoryURL: resolveString(cmd, "repo", repo, m.Repo),
				Version:       resolveString(cmd, "version", version, m.Version),
				ValuesFiles:   resolveValues(cmd, valuesFiles, m.Values),
				Namespace:     resolveString(cmd, "namespace", namespace, m.Namespace),
				ReleaseName:   resolveString(cmd, "release-name", releaseName, m.ReleaseName),
				KubeVersion:   resolveString(cmd, "kube-version", kubeVersion, m.KubeVersion),
			}
			resolvedOutput := resolveString(cmd, "output", outputPath, m.Output)

			if opts.Name == "" {
				return fmt.Errorf(`required "chart" not set: pass --chart, or set it in %s`, manifestPath)
			}
			if opts.RepositoryURL == "" {
				return fmt.Errorf(`required "repo" not set: pass --repo, or set it in %s`, manifestPath)
			}

			bom, err := chart.Generate(opts, logger)
			if err != nil {
				return err
			}

			if len(m.ExtraComponents) > 0 {
				existing := []cdx.Component{}
				if bom.Components != nil {
					existing = *bom.Components
				}
				merged := appendExtraComponents(existing, m.ExtraComponents)
				bom.Components = &merged
			}

			w := cmd.OutOrStdout()
			if resolvedOutput != "" {
				f, err := os.Create(resolvedOutput)
				if err != nil {
					return fmt.Errorf("create output file %s: %w", resolvedOutput, err)
				}
				defer f.Close()
				w = f
			}

			return encodeBOM(w, bom)
		},
	}

	cmd.Flags().StringVar(&chartName, "chart", "", "chart name (required, unless set in the manifest)")
	cmd.Flags().StringVar(&repo, "repo", "", "chart repository URL, classic HTTP(S) or oci:// (required, unless set in the manifest)")
	cmd.Flags().StringVar(&version, "version", "", "chart version (defaults to the latest available)")
	cmd.Flags().StringArrayVarP(&valuesFiles, "values", "f", nil, "values file to merge into the chart's defaults (repeatable)")
	cmd.Flags().StringVar(&namespace, "namespace", "default", "namespace templates are rendered as if installed into")
	cmd.Flags().StringVar(&releaseName, "release-name", "release-name", "release name templates are rendered as if installed under")
	cmd.Flags().StringVar(&kubeVersion, "kube-version", "", "Kubernetes version to render templates and check Chart.yaml's kubeVersion constraint against, e.g. 1.31.0 (defaults to the Helm SDK's own, older built-in default)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "file to write the generated SBOM to (defaults to stdout)")
	cmd.Flags().StringVar(&manifestPath, "manifest", defaultManifestPath, "YAML manifest of default flag values; flags always take precedence, and a manifest at the default path is optional")

	return cmd
}

// encodeBOM writes bom to w as pretty-printed CycloneDX JSON — the exact
// output "sbom generate" must produce on success, per
// plugins/SBOM-CONTRACT.md, whether w is stdout or an --output file.
func encodeBOM(w io.Writer, bom *cdx.BOM) error {
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetEscapeHTML(false)
	enc.SetPretty(true)
	return enc.Encode(bom)
}
