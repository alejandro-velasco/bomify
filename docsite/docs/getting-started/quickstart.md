---
icon: lucide/play
---

# Quickstart

This walks through the same commands as the
[README](https://github.com/alejandro-velasco/bomify#usage)'s Usage section,
with a bit more explanation between steps. It assumes you've already
[installed bomify and the plugins you need](installing-plugins.md).

## 1. Write (or find) an SBOM

bomify builds packages from a CycloneDX SBOM. Each component needs a
[package URL](https://github.com/package-url/purl-spec) (`purl`) bomify can
resolve to a plugin kind. A minimal one, describing a single container
image:

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
    }
  ]
}
```

## 2. Log in to a registry

Only needed if the registry you're pulling from or pushing to requires
authentication — `docker.io` and most public registries don't, for a pull.

```sh
bomify login registry.example.com
```

This uses the same credential store `docker login` does, so credentials from
either tool work for both.

## 3. Build and tag it

```sh
bomify build sbom.json --tag registry.example.com/myapp:1.0
```

Each component is resolved to a plugin by its kind and pulled through it —
in the example above, `bomify-plugin-oci` fetches the `nginx` image. The SBOM
itself is then recorded as this build's manifest, and `--tag` points a
human-readable name at it, the way `docker tag` would.

Add another tag pointing at the same build, without rebuilding:

```sh
bomify tag registry.example.com/myapp:1.0 registry.example.com/myapp:latest
```

## 4. Push it, or pull one that's already there

```sh
bomify push registry.example.com/myapp:1.0
bomify pull registry.example.com/myapp:1.0
```

`push` publishes the whole built package (the SBOM plus every component) as
a single OCI artifact, so it's inspectable and copyable like any other OCI
reference. `pull` does the reverse: it fetches an already-pushed package
without needing the original SBOM file at all.

## 5. Save it to a tarball, and load it back — no registry needed

```sh
bomify save registry.example.com/myapp:1.0 -o myapp.tar
bomify load -i myapp.tar
```

Useful for moving a package to an air-gapped machine, or anywhere a registry
isn't available.

## 6. Clean up

```sh
bomify package remove registry.example.com/myapp:1.0   # or: bomify rmp ...
bomify logout registry.example.com
```

`package remove` untags the package and reclaims anything no other tag still
references.

## Next steps

- [Publish to more than one registry, or mirror by origin](../usage/reference/bomify_distribute.md)
  with `bomify distribute`.
- [Check that every component is fetchable — without downloading anything](../usage/reference/bomify_build.md)
  with `bomify build --check`.
- Browse the full [command reference](../usage/index.md).
