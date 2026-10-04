---
icon: lucide/cloud-upload
---

# Publishing and pulling packages with an OCI registry

`bomify push` publishes a whole package as one OCI artifact (the SBOM as
its config, each component as a layer), with any vulnerability reports
attached alongside. `bomify pull` restores it into another data
directory. Any OCI registry works.

!!! tip "push or distribute?"
    `push` moves the *package* for another bomify to `pull`. To publish
    each *component* to its own native destination (images to an image
    registry, charts to a chart repository), see
    [Distributing a package](distributing-a-package.md).

## 1. Log in

Needed for pushes, and for pulls from private registries:

```sh
bomify login registry.example.com
echo "$REGISTRY_TOKEN" | bomify login registry.example.com -u myuser --password-stdin   # CI
```

Credentials are checked, then stored through bomify's own
`~/.bomify/conf/auth.json` (in the OS credential store when there is
one). Registries you haven't logged into with bomify fall back to your
`docker login` credentials.

!!! note "TLS only"
    bomify only uses HTTPS. Trust a self-signed certificate in the OS
    first, or use the throwaway registry in
    [`deploy/registry/`](https://github.com/alejandro-velasco/bomify/tree/main/deploy/registry).

## 2. Tag with the destination

`push` publishes under the package's local tag, so the tag must be a
full reference (`<registry>/<repository>:<tag>`):

```sh
bomify build sbom.json --tag registry.example.com/myapp:1.0
# or, for an existing package:
bomify tag myapp:1.0 registry.example.com/myapp:1.0
```

## 3. Push

```sh
bomify push registry.example.com/myapp:1.0 --concurrency 6
```

Blobs the registry already has are skipped, so a new version uploads
only what changed. To add a tag like `latest`, tag and push again; only
the tag is written.

```sh
bomify tag registry.example.com/myapp:1.0 registry.example.com/myapp:latest
bomify push registry.example.com/myapp:latest
```

## 4. Inspect without pulling

```sh
bomify package manifest registry.example.com/myapp:1.0 | jq '.components[].purl'
```

The artifact (type `application/vnd.bomify.package.v1+json`) also works
with generic tools like `oras` and `crane`.

## 5. Pull

```sh
bomify pull registry.example.com/myapp:1.0
bomify pull registry.example.com/myapp@sha256:abcdef...   # exact content, no local tag
```

This restores the SBOM, every component, and the newest vulnerability
reports, and records the tag, just as if the package had been built
there.

## Refreshing reports

Re-scan and push again to update a published package's reports:

```sh
bomify security scan grype registry.example.com/myapp:1.0
bomify push registry.example.com/myapp:1.0
```

The package digest, and any signature over it, don't change. Older
report referrers are deleted (`--keep-reports` sets how many stay).
Registries that refuse deletes, like GHCR, keep them; `pull` always uses
the newest, and `bomify security prune` retries the cleanup.
