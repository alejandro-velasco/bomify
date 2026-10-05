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

In a [`bomify sbom compose`](https://github.com/alejandro-velasco/bomify/blob/main/docs/reference/bomify_sbom_compose.md)
file, a `medium: helm` source's `options` take the flags below as keys
(see [Options file](#options-file)). To run the plugin directly, from
`<data-dir>/plugins`:

```
bomify-plugin-helm sbom generate --chart <name> --repo <repository> [flags]
```

The chart is rendered locally, as `helm template` does (no cluster is
contacted). Every image referenced by the pod specs (`containers`,
`initContainers`, `ephemeralContainers`) of `Deployment`, `StatefulSet`,
`DaemonSet`, `Job`, `CronJob`, and `Pod` manifests is reported; custom
resources aren't inspected yet. The chart itself is included too, so the
SBOM can go straight into `bomify build`.

### Flags

| Flag | Required | Meaning |
| --- | --- | --- |
| `--chart` | unless in `--config` | Chart name, e.g. `postgresql`. |
| `--repo` | unless in `--config` | Chart repository: `https://...` or `oci://...`. |
| `--version` | no | Chart version. Defaults to the latest. |
| `--values`, `-f` | no | Values file to merge. Repeatable. |
| `--namespace` | no | `.Release.Namespace`. Default `default`. |
| `--release-name` | no | `.Release.Name`. Default `release-name`, as in `helm template`. |
| `--kube-version` | no | Kubernetes version to render for and to check the chart's `kubeVersion` against, e.g. `1.31.0`. Defaults to the Helm SDK's built-in version; set it to what you deploy to. |
| `--output`, `-o` | no | File to write the SBOM to. Default stdout. |
| `--config` | no | Options file of default flag values, YAML or JSON (see below). Default `bomify-helm-sbom.yaml`, used only if present. `--manifest` is an older name for it. |

### Options file

Any flag but `--output` can be set in an options file instead, keyed by
the flag name:

```yaml
# bomify-helm-sbom.yaml
chart: postgresql
repo: oci://registry-1.docker.io/bitnamicharts
version: 18.11.6
values:
  - values.yaml
```

With that file present, `bomify-plugin-helm sbom generate` needs no
flags. A `bomify sbom compose` source's `options` take the same keys.

- The default `bomify-helm-sbom.yaml` may be absent; an explicit
  `--config` path must exist.
- Command-line flags override the file. An explicit `--values` replaces
  the file's list rather than adding to it.
- Unknown keys are errors.
- `extraComponents` (a list of CycloneDX components) is appended to the
  SBOM as-is, with a missing `bom-ref` set to the component's `purl`. It
  has no flag. Like the rest of the SBOM, each is a CycloneDX component
  (so it needs a `type` and a `name`) with a `purl` (see the
  [SBOM generation contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md#output)).

### Examples

A public OCI chart:

```
bomify-plugin-helm sbom generate --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 18.11.6
```

A chart with a `kubeVersion` constraint and required values, from a
classic chart repository:

```
bomify-plugin-helm sbom generate \
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
