---
icon: lucide/package
---

# Building a package

`bomify build` pulls every component a CycloneDX SBOM describes, through
the plugin for each component's purl type, and records the SBOM as the
build.

## 1. Start from an SBOM

Each component needs a [purl](https://github.com/package-url/purl-spec):

```json title="sbom.json"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "container",
      "name": "nginx",
      "version": "1.27",
      "purl": "pkg:oci/nginx@1.27?repository_url=docker.io/library/nginx"
    },
    {
      "type": "file",
      "name": "config",
      "version": "1.0",
      "purl": "pkg:generic/config@1.0?download_url=https://example.com/config-1.0.tar.gz"
    }
  ]
}
```

Or [generate one from a Helm chart](building-an-sbom-from-a-helm-chart.md).

## 2. Check it without downloading

```sh
bomify build sbom.json --check
```

Each plugin cheaply confirms its component is reachable and authorized.
Nothing is recorded.

## 3. Build and tag

```sh
bomify build sbom.json --tag myapp:1.0 --tag myapp:latest --concurrency 4
```

A component whose SHA-256 doesn't match the SBOM fails the build.

## 4. Find it later

```sh
bomify packages
bomify tag myapp:1.0 myapp:v1.0.1   # another name, no rebuild
```
