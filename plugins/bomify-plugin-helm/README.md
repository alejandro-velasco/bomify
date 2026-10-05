# bomify-plugin-helm

bomify's plugin for Helm charts. It implements two independent contracts:

- **SBOM generation** (`sbom generate`,
  [contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md)):
  renders a chart and reports every image it references. List it as a
  `helm` source in a `bomify sbom compose` file, or run it yourself.
- **Component** (`component pull|push|remote`,
  [contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md)):
  fetches and publishes `pkg:helm/...` charts. `bomify build` and `bomify
  distribute` call these; you normally don't.

## SBOM generation

List the chart as a `medium: helm` source in a
[`bomify sbom compose`](https://github.com/alejandro-velasco/bomify/blob/main/docs/reference/bomify_sbom_compose.md)
file, with the options below. To run the plugin directly, from
`<data-dir>/plugins`, put them in an options file:

```
bomify-plugin-helm sbom generate [--config <file>] [--output <file>]
```

The chart is rendered locally, as `helm template` does (no cluster is
contacted). Every image referenced by the pod specs (`containers`,
`initContainers`, `ephemeralContainers`) of `Deployment`, `StatefulSet`,
`DaemonSet`, `Job`, `CronJob`, and `Pod` manifests is reported; custom
resources aren't inspected yet. The chart itself is included too, so the
SBOM can go straight into `bomify build`.

### Options

| Key | Required | Meaning |
| --- | --- | --- |
| `chart` | yes | Chart name, e.g. `postgresql`. |
| `repo` | yes | Chart repository: `https://...` or `oci://...`. |
| `version` | no | Chart version. Defaults to the latest. |
| `values` | no | Values files to merge, in order. |
| `namespace` | no | `.Release.Namespace`. Default `default`. |
| `release-name` | no | `.Release.Name`. Default `release-name`, as in `helm template`. |
| `kube-version` | no | Kubernetes version to render for and to check the chart's `kubeVersion` against, e.g. `1.31.0`. Defaults to the Helm SDK's built-in version; set it to what you deploy to. |

To package anything rendering can't discover, list it under the
composition file's `components`.

Unknown keys are errors. Run directly, the plugin reads them from
`--config`, YAML or JSON, or else from `bomify-helm-sbom.yaml` in the
working directory if present; `--output` writes the SBOM to a file
instead of stdout.

### Example

A chart with a `kubeVersion` constraint and required values, from a
classic chart repository:

```yaml
# bomify-helm-sbom.yaml
chart: enterprise
repo: https://charts.anchore.io
version: 4.4.0
kube-version: 1.31.0
values: [values.yaml]
```

```yaml
# values.yaml
postgresql:
  externalEndpoint: postgres.example.com
  auth:
    username: anchore
    password: placeholder
    database: anchore
```

Values a chart requires in order to render at all (an external database
host, a secret name) need placeholders even for an SBOM, just as for
`helm template`.
