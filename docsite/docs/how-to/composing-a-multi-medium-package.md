---
icon: lucide/combine
---

# Composing a multi-medium package

An application often ships through more than one medium: say, two Helm
charts plus a vendored tool. `bomify sbom compose` merges their SBOMs
into one, which `bomify build` then builds as one package.

## 1. Write a composition file

```yaml
# bomify.yaml
name: myapp
version: 1.4.0
sources:
  - name: web
    medium: helm
    options:
      chart: web
      repo: oci://registry.example.com/charts
      version: 2.1.0
      values: [values/web.yaml]
  - name: db
    medium: helm
    options:
      chart: postgresql
      repo: oci://registry-1.docker.io/bitnamicharts
      version: 15.6.0
  - name: tools
    sbom: vendor/tools.cdx.json
components:
  - type: file
    name: migrate
    purl: pkg:generic/migrate@3.1?download_url=https://example.com/migrate-3.1.tar.gz
    hashes:
      - alg: SHA-256
        content: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

- A `medium` source runs `bomify-plugin-<medium>`, with `options` as
  its options, which that plugin checks; for Helm, they're the
  [plugin's flags](https://github.com/alejandro-velasco/bomify/blob/main/plugins/bomify-plugin-helm/README.md#options-file).
- An `sbom` source is an existing CycloneDX JSON file.
- `components` are packaged too.
- Relative paths, in `options` too, are relative to the composition
  file. Paths inside an `sbom` file, such as a plugin binary's
  `distribution` path, are copied as they are, so `bomify build`
  resolves them against the composed SBOM: write it where they still
  make sense.

Every SBOM, whether generated or read from a file, must follow the
[SBOM generation contract's output rules](../development/sbom-contract.md#output):
for example, each component needs a `purl`, and its `bom-ref` is that
purl.

## 2. Compose it

```sh
bomify sbom compose bomify.yaml -o myapp.cdx.json
```

Every medium's plugin is found before any runs. Components appearing in
several sources, like an image both charts use, are merged
by purl; each records the sources it came from in its
`land.bomify.compose.sources` property. Two sources disagreeing on the
same purl's version or hashes stop the compose.

The same sources always compose the same file, so you can commit it and
review its changes.

## 3. Build it

```sh
bomify build myapp.cdx.json --tag myapp:1.4.0
```

From here it's an ordinary package: [scan it](scanning-with-grype.md),
[sign and push it](signing-and-verifying-packages.md), or
[distribute it](distributing-a-package.md).
