package chart

import (
	"fmt"
	"log/slog"
	"path"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/package-url/packageurl-go"
	"helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"

	"github.com/alejandro-velasco/bomify/pkg/auth"
)

// GenerateOptions identifies the chart Generate should render and how to
// render it. Unlike Ref (which Resolve derives from a component purl for
// pull/push), these come directly from "sbom generate"'s own flags — see
// plugins/SBOM-CONTRACT.md, which leaves this entirely up to the plugin.
type GenerateOptions struct {
	// Name is the chart's name, e.g. "postgresql".
	Name string
	// Version is the chart version to render, e.g. "15.6.0". Empty means
	// whatever the repository/registry reports as latest.
	Version string
	// RepositoryURL is a classic HTTP(S) chart repository base URL or an
	// "oci://" registry reference, exactly like Ref.RepositoryURL.
	RepositoryURL string
	// ValuesFiles are merged into the chart's default values, in the
	// order given, exactly like repeated "helm template -f" flags.
	ValuesFiles []string
	// Namespace is the namespace templates are rendered as if installed
	// into (.Release.Namespace). Defaults to "default".
	Namespace string
	// ReleaseName is the release name templates are rendered as if
	// installed under (.Release.Name). Defaults to "release-name" —
	// the same default the "helm template" CLI command itself uses.
	ReleaseName string
	// KubeVersion overrides the Kubernetes version templates see via
	// .Capabilities.KubeVersion and a chart's own Chart.yaml
	// "kubeVersion" constraint is checked against, e.g. "1.31.0". Empty
	// leaves the Helm SDK's own built-in default in place — the same
	// "helm template" falls back to with no "--kube-version" of its
	// own — which is old enough that a chart requiring a recent
	// Kubernetes version will otherwise fail to render with an
	// "incompatible with Kubernetes" error.
	KubeVersion string
}

// Generate renders opts' chart's templates locally — the same code path
// behind "helm template" (a client-only, dry-run "helm install") — and
// returns a CycloneDX SBOM listing every container image the rendered
// manifests reference, discovered from the well-known pod-spec locations
// of a Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod (see
// discoverImages). It never contacts a Kubernetes cluster: only the
// chart repository/registry opts.RepositoryURL names.
func Generate(opts GenerateOptions, logger *slog.Logger) (*cdx.BOM, error) {
	namespace := opts.Namespace
	if namespace == "" {
		namespace = "default"
	}
	releaseName := opts.ReleaseName
	if releaseName == "" {
		releaseName = "release-name"
	}

	host := registryHost(opts.RepositoryURL)
	registryClient, err := newRegistryClient(host)
	if err != nil {
		return nil, err
	}

	install := action.NewInstall(&action.Configuration{RegistryClient: registryClient})
	install.ClientOnly = true
	install.DryRun = true
	install.Namespace = namespace
	install.ReleaseName = releaseName
	install.Version = opts.Version

	if opts.KubeVersion != "" {
		kubeVersion, err := chartutil.ParseKubeVersion(opts.KubeVersion)
		if err != nil {
			return nil, fmt.Errorf("parse kube version %q: %w", opts.KubeVersion, err)
		}
		install.KubeVersion = kubeVersion
	}

	settings := cli.New()

	// Mirrors Pull's own OCI-vs-classic-repo branching (transfer.go): for
	// OCI, LocateChart wants a bare "oci://host/path/<name>" ref with no
	// separate RepoURL; for a classic repo, it wants just the chart name,
	// with the repo's base URL supplied via RepoURL instead.
	chartRef := opts.Name
	if registry.IsOCI(opts.RepositoryURL) {
		chartRef = strings.TrimSuffix(opts.RepositoryURL, "/") + "/" + opts.Name
	} else {
		install.RepoURL = opts.RepositoryURL

		if host != "" {
			username, password, err := auth.Get(host)
			if err != nil {
				return nil, fmt.Errorf("look up credentials for %s: %w", host, err)
			}
			install.Username = username
			install.Password = password
		}
	}

	logger.Info("locating chart", "chart", chartRef, "version", opts.Version, "repository_url", opts.RepositoryURL)
	chartPath, err := install.ChartPathOptions.LocateChart(chartRef, settings)
	if err != nil {
		return nil, fmt.Errorf("locate chart %s@%s from %s: %w", opts.Name, opts.Version, opts.RepositoryURL, err)
	}

	chrt, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("load chart %s: %w", chartPath, err)
	}

	vals, err := (&values.Options{ValueFiles: opts.ValuesFiles}).MergeValues(getter.All(settings))
	if err != nil {
		return nil, fmt.Errorf("load values: %w", err)
	}

	logger.Info("rendering chart templates", "chart", chrt.Name(), "version", chartVersion(chrt))
	rel, err := install.Run(chrt, vals)
	if err != nil {
		return nil, fmt.Errorf("render chart templates: %w", err)
	}

	images, err := discoverImages(rel.Manifest)
	if err != nil {
		return nil, fmt.Errorf("discover images: %w", err)
	}
	logger.Info("discovered images", "count", len(images))

	return buildBOM(chrt, opts.RepositoryURL, images)
}

// chartVersion returns chrt's declared version, or "" if it has no
// metadata at all (a chart missing Chart.yaml would already have failed
// to load, but Metadata is still a pointer).
func chartVersion(chrt *helmchart.Chart) string {
	if chrt.Metadata == nil {
		return ""
	}
	return chrt.Metadata.Version
}

// buildBOM builds the CycloneDX SBOM Generate returns: chrt itself
// (including its own pkg:helm purl, built from repositoryURL — the same
// chart ref Generate rendered) as both the SBOM's top-level metadata
// component (the conventional CycloneDX "what does this BOM describe")
// and the first entry of its component list — the latter so the chart
// itself, not just the images it references, is something "bomify
// build" (which only ever walks a BOM's Components, never its
// Metadata.Component) can pull into a package.
func buildBOM(chrt *helmchart.Chart, repositoryURL string, images []imageRef) (*cdx.BOM, error) {
	bom := cdx.NewBOM()

	components := make([]cdx.Component, 0, len(images)+1)

	if chrt.Metadata != nil {
		chartComponent := cdx.Component{
			Type:       cdx.ComponentTypeApplication,
			Name:       chrt.Metadata.Name,
			Version:    chrt.Metadata.Version,
			PackageURL: chartPurl(chrt.Metadata.Name, chrt.Metadata.Version, repositoryURL),
		}
		bom.Metadata = &cdx.Metadata{Component: &chartComponent}
		components = append(components, chartComponent)
	}

	for _, img := range images {
		component, err := imageComponent(img.Reference)
		if err != nil {
			return nil, fmt.Errorf("build component for image %q (found in %s): %w", img.Reference, img.Source, err)
		}
		components = append(components, component)
	}
	bom.Components = &components

	return bom, nil
}

// imageComponent builds the CycloneDX component describing the container
// image ref names, including a pkg:oci purl in the same shape
// bomify-plugin-oci's own Resolve/Location expect to parse back (see
// plugins/bomify-plugin-oci/internal/image/resolve.go's repositoryFor) —
// so a component this SBOM describes is, if the user chooses to feed
// this SBOM into "bomify build", directly usable without translation.
func imageComponent(ref string) (cdx.Component, error) {
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return cdx.Component{}, fmt.Errorf("parse image reference %q: %w", ref, err)
	}

	repository := parsed.Context()
	imageName := path.Base(repository.RepositoryStr())

	var version string
	switch r := parsed.(type) {
	case name.Digest:
		version = r.DigestStr()
	case name.Tag:
		version = r.TagStr()
	}

	qualifiers := packageurl.QualifiersFromMap(map[string]string{"repository_url": repository.Name()})
	purl := packageurl.NewPackageURL(packageurl.TypeOCI, "", imageName, version, qualifiers, "")

	return cdx.Component{
		Type:       cdx.ComponentTypeContainer,
		Name:       imageName,
		Version:    version,
		PackageURL: purl.String(),
	}, nil
}

// chartPurl builds the pkg:helm purl identifying the chart Generate just
// rendered, in exactly the shape this same plugin's own Resolve expects
// to parse back (see resolve.go) — so, like imageComponent's pkg:oci
// purls, the SBOM's own top-level component is itself directly usable as
// a "bomify build" component if the user chooses to.
func chartPurl(name, version, repositoryURL string) string {
	qualifiers := packageurl.QualifiersFromMap(map[string]string{"repository_url": repositoryURL})
	return packageurl.NewPackageURL(packageurl.TypeHelm, "", name, version, qualifiers, "").String()
}
