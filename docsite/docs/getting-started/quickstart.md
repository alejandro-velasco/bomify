---
icon: lucide/play
---

# Quickstart

Assumes bomify and its plugins are [installed](installation.md).

## 1. Write an SBOM

bomify builds packages from CycloneDX SBOMs. Each component needs a
[purl](https://github.com/package-url/purl-spec), whose type picks the
plugin that fetches it:

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

## 2. Build and tag it

```sh
bomify build sbom.json --tag registry.example.com/myapp:1.0
bomify tag registry.example.com/myapp:1.0 registry.example.com/myapp:latest
```

`bomify-plugin-oci` fetches the image, and the tag names the build, as
`docker tag` would.

## 3. Push and pull it

```sh
bomify login registry.example.com
bomify push registry.example.com/myapp:1.0
bomify pull registry.example.com/myapp:1.0
```

The package travels as one OCI artifact; `pull` doesn't need the
original SBOM.

## 4. Move it without a registry

```sh
bomify save registry.example.com/myapp:1.0 -o myapp.tar
bomify load -i myapp.tar
```

## 5. Clean up

```sh
bomify rmp registry.example.com/myapp:1.0
bomify logout registry.example.com
```

`rmp` untags the package and removes anything no other tag uses.

Next, see the [how-to guides](../how-to/index.md) or the
[command reference](../usage/index.md).
