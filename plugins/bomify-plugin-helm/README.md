# bomify-plugin-helm

bomify's first-party plugin for Helm charts. It implements two entirely
independent plugin classes — see [`plugins/COMPONENT-CONTRACT.md`](../COMPONENT-CONTRACT.md)
and [`plugins/SBOM-CONTRACT.md`](../SBOM-CONTRACT.md) for the full specs:

- **SBOM generation** (`sbom generate`) — renders a chart's templates and
  reports every container image it references as a CycloneDX SBOM. This
  is the one meant to be run directly; see below.
- **Component** (`component pull`/`component push`/`component remote`) —
  fetches/publishes one Helm chart component at a time. `bomify build`
  and `bomify distribute` invoke this internally; see
  [Component commands](#component-commands) for why you normally
  shouldn't call it yourself.

## SBOM generation

```
bomify sbom generate helm --chart <name> --repo <repository> [flags]
```

`bomify sbom generate helm ...` is how you'd normally run this — the
`bomify` orchestrator just locates `bomify-plugin-helm` on `PATH` and
execs `bomify-plugin-helm sbom generate ...` with every flag after
`helm` passed through unchanged (see
[`plugins/SBOM-CONTRACT.md`](../SBOM-CONTRACT.md)). Running the plugin
directly is exactly equivalent, so the examples below use whichever form
reads better:

```
bomify-plugin-helm sbom generate --chart <name> --repo <repository> [flags]
```

`sbom generate` fetches the chart, renders its templates locally via the
Helm SDK (the same code path as `helm template` — no cluster is ever
contacted), then walks the rendered `Deployment`/`StatefulSet`/
`DaemonSet`/`Job`/`CronJob`/`Pod` manifests for every container image
their pod specs reference (`containers`, `initContainers`,
`ephemeralContainers`). Custom resources aren't inspected yet. The chart
itself is included as a component too (with its own `pkg:helm` purl), not
just the images it references, so the resulting SBOM can be fed straight
into `bomify build` to pull both.

### Flags

| Flag | Required | Meaning |
| --- | --- | --- |
| `--chart` | yes, unless set in the manifest | Chart name, e.g. `postgresql`. |
| `--repo` | yes, unless set in the manifest | Chart repository URL — a classic `https://...` chart repo or an `oci://...` registry. |
| `--version` | no | Chart version. Defaults to whatever the repository reports as latest. |
| `--values`, `-f` | no | Values file to merge into the chart's defaults. Repeatable. |
| `--namespace` | no | Namespace templates are rendered as if installed into (`.Release.Namespace`). Defaults to `default`. |
| `--release-name` | no | Release name templates are rendered as if installed under (`.Release.Name`). Defaults to `release-name`, same as `helm template`. |
| `--kube-version` | no | Kubernetes version to render against and check a chart's own `kubeVersion` constraint in `Chart.yaml` against, e.g. `1.31.0`. Rendering never touches a real cluster, so this otherwise falls back to the Helm SDK's own, rather old, built-in default — a chart requiring a recent Kubernetes version will fail to render with an "incompatible with Kubernetes" error unless this is set high enough. |
| `--output`, `-o` | no | File to write the generated SBOM to. Defaults to stdout. |
| `--manifest` | no | YAML manifest of default flag values (see below). Defaults to `bomify-helm-sbom.yaml`, read only if present. |

### Manifest file

Every flag above can instead be set in a YAML manifest, keyed by the same
flag names, so a chart with a long, reusable set of options doesn't need
them typed out on every run:

```yaml
# bomify-helm-sbom.yaml
chart: postgresql
repo: oci://registry-1.docker.io/bitnamicharts
version: 18.11.6
values:
  - values.yaml
output: postgresql.cdx.json
```

`--manifest` defaults to `bomify-helm-sbom.yaml` in the working
directory — present or not, that default is never an error. A path
given explicitly via `--manifest` must exist. Either way, **a flag given
explicitly on the command line always takes precedence over the same key
in the manifest**; `--values` is all-or-nothing (an explicit `--values`
replaces the manifest's `values` list, it doesn't merge with it).

With the manifest above, generating the SBOM is just:

```
bomify sbom generate helm
```

### Examples

A public OCI chart, no values needed:

```
bomify sbom generate helm --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 18.11.6
```

A chart with its own `kubeVersion` constraint (`>=1.23.0-0`), and
required values (a classic HTTP(S) chart repo, not OCI):

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

A large umbrella chart with several required external-service values:

```
bomify sbom generate helm \
  --chart gitlab --repo https://charts.gitlab.io --version 10.4.1 \
  --values values.yaml
```

```yaml
# values.yaml
certmanager-issuer:
  email: admin@example.com
global:
  hosts:
    domain: example.com
  redis:
    host: redis.example.com
  psql:
    host: postgresql.example.com
    password:
      secret: gitlab-postgresql-password
  appConfig:
    object_store:
      enabled: true
      connection:
        secret: gitlab-object-storage
registry:
  storage:
    secret: gitlab-registry-storage
```

These required values are specific to each chart, not something this
plugin imposes — anything a chart's templates `require` to render at all
(an external database host, a notification email, a secret name) needs a
placeholder here even for a metadata-only SBOM pass, exactly as it would
for a real `helm template`/`helm install --dry-run`.

## Component commands

`component pull`, `component push`, and `component remote` implement the
[component plugin contract](../COMPONENT-CONTRACT.md) — the machinery
`bomify build` and `bomify distribute` use internally to fetch and
publish one Helm chart component (resolved from a `pkg:helm/...` purl) at
a time. You shouldn't normally invoke these yourself: run `bomify build`/
`bomify distribute` instead, and they'll find and call this plugin
automatically. See `plugins/COMPONENT-CONTRACT.md` for the full
subprocess contract (flags, JSON result shapes, `--check` mode) if you're
implementing or debugging a plugin rather than just using one.
