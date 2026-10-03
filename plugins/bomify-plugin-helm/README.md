# bomify-plugin-helm

bomify's plugin for Helm charts. It implements two independent contracts:

- **SBOM generation** (`sbom generate`,
  [contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md)):
  renders a chart and reports every image it references. Run this one
  yourself.
- **Component** (`component pull|push|remote`,
  [contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md)):
  fetches and publishes `pkg:helm/...` charts. `bomify build` and `bomify
  distribute` call these; you normally don't.

## SBOM generation

```
bomify sbom generate helm --chart <name> --repo <repository> [flags]
```

bomify passes every flag after `helm` straight to `bomify-plugin-helm sbom
generate`, so running the plugin directly is equivalent.

The chart is rendered locally, as `helm template` does (no cluster is
contacted). Every image referenced by the pod specs (`containers`,
`initContainers`, `ephemeralContainers`) of `Deployment`, `StatefulSet`,
`DaemonSet`, `Job`, `CronJob`, and `Pod` manifests is reported; custom
resources aren't inspected yet. The chart itself is included too, so the
SBOM can go straight into `bomify build`.

### Flags

| Flag | Required | Meaning |
| --- | --- | --- |
| `--chart` | unless in the manifest | Chart name, e.g. `postgresql`. |
| `--repo` | unless in the manifest | Chart repository: `https://...` or `oci://...`. |
| `--version` | no | Chart version. Defaults to the latest. |
| `--values`, `-f` | no | Values file to merge. Repeatable. |
| `--namespace` | no | `.Release.Namespace`. Default `default`. |
| `--release-name` | no | `.Release.Name`. Default `release-name`, as in `helm template`. |
| `--kube-version` | no | Kubernetes version to render for and to check the chart's `kubeVersion` against, e.g. `1.31.0`. Defaults to the Helm SDK's built-in version; set it to what you deploy to. |
| `--output`, `-o` | no | File to write the SBOM to. Default stdout. |
| `--manifest` | no | YAML file of default flag values (see below). Default `bomify-helm-sbom.yaml`, used only if present. |

### Manifest file

Any flag can be set in a YAML manifest instead, keyed by the flag name:

```yaml
# bomify-helm-sbom.yaml
chart: postgresql
repo: oci://registry-1.docker.io/bitnamicharts
version: 18.11.6
values:
  - values.yaml
output: postgresql.cdx.json
```

With that file present, `bomify sbom generate helm` needs no flags.

- The default `bomify-helm-sbom.yaml` may be absent; an explicit
  `--manifest` path must exist.
- Command-line flags override the manifest. An explicit `--values`
  replaces the manifest's list rather than adding to it.
- `extraComponents` (a list of CycloneDX components) is appended to the
  SBOM as-is. It has no flag and isn't validated.

### Examples

A public OCI chart:

```
bomify sbom generate helm --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 18.11.6
```

A chart with a `kubeVersion` constraint and required values, from a
classic chart repository:

```
bomify sbom generate helm \
  --chart enterprise --repo https://charts.anchore.io --version 4.4.0 \
  --kube-version 1.31.0 \
  --values values.yaml
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
