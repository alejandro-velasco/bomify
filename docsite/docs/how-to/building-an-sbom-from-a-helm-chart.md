---
icon: lucide/anchor
---

# Building an SBOM from a Helm chart

`bomify-plugin-helm` renders a chart locally (as `helm template` does,
with no cluster) and reports every image it references, plus the chart,
as a CycloneDX SBOM. Install it with `bomify plugin install helm`. Its
[README](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-helm/README.md)
lists every flag and the options file format.

## 1. Generate an SBOM

```sh
bomify sbom generate helm \
  --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 18.11.6 \
  --output postgresql.cdx.json
```

`--repo` takes `https://...` or `oci://...`. Without `--version`, the
latest is used.

## 2. Supply required values

Values a chart needs in order to render at all need placeholders, as for
`helm template`. Set `--kube-version` to your cluster's version so the
chart renders (and checks its `kubeVersion`) as it would there.

```sh
bomify sbom generate helm \
  --chart enterprise --repo https://charts.anchore.io --version 4.4.0 \
  --kube-version 1.31.0 --values values.yaml
```

To avoid retyping flags, put them in `bomify-helm-sbom.yaml` and run
`bomify sbom generate helm` with none.

## 3. Build it

```sh
bomify build postgresql.cdx.json --tag postgresql:18.11.6
```

Then [scan it](scanning-with-grype.md) or
[distribute it](distributing-a-package.md).
