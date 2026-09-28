---
icon: lucide/shield-alert
---

# Scanning a package's components with grype

`bomify security scan` resolves a security scanning plugin by name
(not by purl type, since any scanner can in principle scan any
component), asks it which purl types it supports, and calls it once
per supported component of a built package, storing each result as
that component's own vulnerability report. `bomify-plugin-grype` is
bomify's first-party scanner, backed by
[Anchore's grype](https://github.com/anchore/grype).
See [bomify security scan](../usage/reference/bomify_security_scan.md)
for the full flag reference,
[ARCHITECTURE.md](https://github.com/alejandro-velasco/bomify/blob/main/ARCHITECTURE.md#security-scanning)
for how reports are laid out, and
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#bomify-plugin-grype)
for how the plugin itself works.

Requires [`bomify-plugin-grype`](../getting-started/installing-plugins.md)
to be on `PATH`.

## 1. Scan a package

The package must already exist locally — built with `bomify build`, or
fetched with `bomify pull`/`bomify load`:

```sh
bomify build sbom.cdx.json --tag myapp:1.0
bomify security scan grype myapp:1.0
```

Each scanned component gets its own CycloneDX vulnerability report at
`<data-dir>/vulnerabilities/<purl-hash>.json`, keyed by the same purl
hash as its pulled layer — so a component two packages share also
shares one report, and scanning either package refreshes it. A summary
of every scanned component, with its vulnerability count and report ID
(the first 12 characters of that hash), is printed to stdout.

## 2. Scan container images, not just named packages

Most purl types (`npm`, `pypi`, `maven`, `apk`, ...) already name one
specific package, so grype matches it directly: the report's metadata
component is that package, and each vulnerability's `affects` points
back at it. An `oci`/`docker` component names a whole image instead —
for those, the plugin catalogs the image with
[Anchore's syft](https://github.com/anchore/syft) first (the same code
path `grype <image>` itself uses), then matches every package it finds
inside. The image stays the report's metadata component, and each
cataloged package becomes one of the report's top-level components,
with its own `evidence.occurrences` tracing back to where syft found it
(an apk/dpkg entry, a `package.json`, a jar on disk, ...) and each
vulnerability's `affects` pointing at the specific package(s) affected.

Image pulling for these uses syft's own default source resolution: the
local Docker/Podman daemon if present, otherwise the registry directly
via whatever credentials `docker login`/`crane auth login` populated —
not bomify's own `bomify login` store.

## 3. Scan several components concurrently

```sh
bomify security scan grype myapp:1.0 --concurrency 4
```

## 4. Skip unsupported components

Any component whose purl type isn't in grype's own
`security supported-components` list (roughly: the OS/language
ecosystems grype has a dedicated matcher for, plus `oci`/`docker` —
notably not `generic`, since there's no image or package to look up
for it) is skipped automatically, and gets no report; you don't need to
filter the SBOM yourself first.

## Next steps

- [Distributing a package](distributing-a-package.md) once you're
  satisfied with what the scan turned up.
- [Building an SBOM from a Helm chart](building-an-sbom-from-a-helm-chart.md)
  as one way to produce an SBOM worth building and scanning in the first
  place.
