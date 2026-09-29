---
icon: lucide/anchor
---

# Building an SBOM from a Helm chart

`bomify-plugin-helm` implements the independent SBOM generation
contract's `sbom generate`: it renders a chart's templates locally via
the Helm SDK (the same code path as `helm template` — no cluster is
ever contacted) and reports every container image the rendered
`Deployment`/`StatefulSet`/`DaemonSet`/`Job`/`CronJob`/`Pod` manifests
reference, plus the chart itself, as a CycloneDX SBOM. See
[bomify sbom generate](../usage/reference/bomify_sbom_generate.md) and
the plugin's own
[README](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-helm/README.md)
for the complete flag list.

Requires [`bomify-plugin-helm`](../getting-started/installing-plugins.md)
to be installed (`bomify plugin install helm`).

## 1. Generate an SBOM for a public chart

```sh
bomify sbom generate helm \
  --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 18.11.6 \
  --output postgresql.cdx.json
```

`--repo` accepts either a classic `https://...` chart repository or an
`oci://...` registry. Omitting `--version` uses whatever the
repository reports as latest.

## 2. Supply values a chart's templates require

Rendering never touches a real cluster, so anything a chart's
templates `require` to render at all — an external database host, a
notification email, a secret name — needs a placeholder value, exactly
as it would for a real `helm template`/`helm install --dry-run`:

```yaml title="values.yaml"
postgresql:
  externalEndpoint: postgres.example.com
  auth:
    username: anchore
    password: placeholder
    database: anchore
```

```sh
bomify sbom generate helm \
  --chart enterprise --repo https://charts.anchore.io --version 4.4.0 \
  --kube-version 1.31.0 \
  --values values.yaml
```

`--kube-version` also matters here: with no real cluster to check
against, rendering otherwise falls back to the Helm SDK's own
built-in default — the Kubernetes version matching the client
libraries the plugin was built with, not necessarily the one you
deploy to. Set it to your cluster's version so templates render as
they would there, and a chart that doesn't support it fails with an
"incompatible with Kubernetes" error instead of rendering anyway.

## 3. Reuse a manifest instead of retyping flags

Every flag above can instead live in a YAML manifest, read by default
from `bomify-helm-sbom.yaml` in the working directory:

```yaml title="bomify-helm-sbom.yaml"
chart: postgresql
repo: oci://registry-1.docker.io/bitnamicharts
version: 18.11.6
values:
  - values.yaml
output: postgresql.cdx.json
```

```sh
bomify sbom generate helm
```

A flag given explicitly on the command line always takes precedence
over the same key in the manifest.

## 4. Build the SBOM you just generated

The generated SBOM is a normal CycloneDX SBOM, so it feeds straight
into [Building a package](building-a-package.md):

```sh
bomify build postgresql.cdx.json --tag postgresql:18.11.6
```

## Next steps

- [Scanning a package's components with grype](scanning-with-grype.md)
  to check the images this SBOM references for known vulnerabilities.
- [Distributing a package](distributing-a-package.md) once it's built.
