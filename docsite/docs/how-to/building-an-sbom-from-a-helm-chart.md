---
icon: lucide/anchor
---

# Building an SBOM from a Helm chart

`bomify-plugin-helm` renders a chart locally (as `helm template` does,
with no cluster) and reports every image it references, plus the chart,
as a CycloneDX SBOM. Install it with `bomify plugin install helm`. Its
[README](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-helm/README.md#flags)
lists every option.

## 1. Describe the chart

A composition file with one Helm source:

```yaml
# bomify.yaml
name: postgresql
version: 18.11.6
sources:
  - name: postgresql
    medium: helm
    options:
      chart: postgresql
      repo: oci://registry-1.docker.io/bitnamicharts
      version: 18.11.6
```

`repo` takes `https://...` or `oci://...`. Without `version`, the latest
is used.

## 2. Supply required values

Values a chart needs in order to render at all need placeholders, as for
`helm template`. Set `kube-version` to your cluster's version so the
chart renders (and checks its `kubeVersion`) as it would there:

```yaml
    options:
      chart: enterprise
      repo: https://charts.anchore.io
      version: 4.4.0
      kube-version: 1.31.0
      values: [values.yaml]
```

## 3. Compose and build it

```sh
bomify sbom compose bomify.yaml -o postgresql.cdx.json
bomify build postgresql.cdx.json --tag postgresql:18.11.6
```

To add more charts, images, or files to the same package, list them as
more sources; see
[Composing a multi-medium package](composing-a-multi-medium-package.md).
Then [scan it](scanning-with-grype.md) or
[distribute it](distributing-a-package.md).
