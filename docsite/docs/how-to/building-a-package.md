---
icon: lucide/package
---

# Building a package

`bomify build` reads a CycloneDX SBOM and pulls every component it
describes through the plugin matching that component's purl type,
then records the SBOM itself as this build's manifest so later
commands (`push`, `distribute`, `tag`, `packages`) can find it. See
[bomify build](../usage/reference/bomify_build.md) for the full flag
reference.

## 1. Start from an SBOM

Each component needs a [package URL](https://github.com/package-url/purl-spec)
bomify can resolve to a plugin kind:

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

You don't have to write one by hand — see
[Building an SBOM from a Helm chart](building-an-sbom-from-a-helm-chart.md)
for one way to generate one instead.

## 2. Check it first, without downloading anything

```sh
bomify build sbom.json --check
```

`--check` asks each component's plugin to confirm it's pullable and
authorized — an inexpensive existence/auth check, not a real
download — and skips recording a build, since nothing was actually
pulled. Useful in CI before committing to a real build, or after
editing an SBOM by hand.

## 3. Build and tag it

```sh
bomify build sbom.json --tag myapp:1.0 --tag myapp:latest
```

`--tag` is repeatable, so one build can be reachable under several
names at once. Pull components concurrently while you're at it:

```sh
bomify build sbom.json --tag myapp:1.0 --concurrency 4
```

Each pulled component is checked against its SBOM-declared SHA-256; a
mismatch fails the build.

## 4. Find it again later

```sh
bomify packages
```

Add another tag pointing at the same build, without rebuilding or
re-pulling anything:

```sh
bomify tag myapp:1.0 myapp:v1.0.1
```

## Next steps

- [Distributing a package](distributing-a-package.md) to publish what
  you just built.
- [Saving packages for airgapped environments](saving-packages-for-airgapped-environments.md)
  if the destination has no registry access at all.
