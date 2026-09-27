---
icon: lucide/shield-alert
---

# Scanning an SBOM's components with grype

`bomify security scan` resolves a security scanning plugin by name
(not by purl type, since any scanner can in principle scan any
component), asks it which purl types it supports, and calls it once
per supported component to populate the SBOM's own
`vulnerabilities`. `bomify-plugin-grype` is bomify's first-party
scanner, backed by [Anchore's grype](https://github.com/anchore/grype).
See [bomify security scan](../usage/reference/bomify_security_scan.md)
for the full flag reference, and
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#bomify-plugin-grype)
for how the plugin itself works.

Requires [`bomify-plugin-grype`](../getting-started/installing-plugins.md)
to be on `PATH`.

## 1. Scan an SBOM

```sh
bomify security scan grype sbom.cdx.json --output scanned.cdx.json
```

The scanned SBOM — with `vulnerabilities` populated, each one's
`affects` pointing back at the specific component(s) it applies to —
is printed to stdout by default; `--output` writes it to a file
instead.

## 2. Scan container images, not just named packages

Most purl types (`npm`, `maven`, `apk`, ...) already name one specific
package, so grype matches it directly. An `oci`/`docker` component
names a whole image instead — for those, the plugin catalogs the image
with [Anchore's syft](https://github.com/anchore/syft) first (the same
code path `grype <image>` itself uses), then matches every package it
finds inside. Each cataloged package comes back as a nested component
under the image, with its own `evidence.occurrences` tracing back to
where syft found it (an apk/dpkg entry, a `package.json`, a jar on
disk, ...), so `bomify security scan` can embed it as the image's own
nested component rather than losing that detail.

Image pulling for these uses syft's own default source resolution: the
local Docker/Podman daemon if present, otherwise the registry directly
via whatever credentials `docker login`/`crane auth login` populated —
not bomify's own `bomify login` store.

## 3. Scan several components concurrently

```sh
bomify security scan grype sbom.cdx.json --concurrency 4
```

## 4. Skip unsupported components

Any component whose purl type isn't in grype's own
`security supported-components` list (roughly: the OS/language
ecosystems grype has a dedicated matcher for, plus `oci`/`docker` —
notably not `generic`, since there's no image or package to look up
for it) is skipped automatically; you don't need to filter the SBOM
yourself first.

## Next steps

- [Distributing a package](distributing-a-package.md) once you're
  satisfied with what the scan turned up.
- [Building an SBOM from a Helm chart](building-an-sbom-from-a-helm-chart.md)
  as one way to produce an SBOM worth scanning in the first place.
