---
icon: lucide/cloud-upload
---

# Publishing and pulling packages with an OCI registry

`bomify push` publishes a whole built package as a single OCI artifact:
its SBOM manifest as the artifact's config and each component as a
layer. `bomify pull` downloads it back into another machine's data
directory exactly as `bomify build` would have laid it out. Any
OCI-compliant registry works (Docker Hub, GHCR, Harbor, ECR, a
self-hosted `registry:3`, …). See
[bomify push](../usage/reference/bomify_push.md),
[bomify pull](../usage/reference/bomify_pull.md), and
[bomify login](../usage/reference/bomify_login.md) for the full flag
reference.

!!! tip "push or distribute?"
    `push` moves the *package*: one artifact, one reference, that
    another bomify can `pull`. To publish each *component* to its own
    native destination (images to an image registry, charts to a chart
    repository, …) so non-bomify tooling can use them, see
    [Distributing a package](distributing-a-package.md) instead.

## 1. Log in to the registry

Skip this if the registry allows anonymous access for what you're
doing (most public registries do for a pull, never for a push).

```sh
# Prompt for username and password
bomify login registry.example.com

# Non-interactively, e.g. in CI
echo "$REGISTRY_TOKEN" | bomify login registry.example.com -u myuser --password-stdin
```

`bomify login` checks the credentials against the registry before
storing them, in the same `~/.docker/config.json` and OS credential
store `docker login` uses. A registry you've already logged in to with
`docker login` works as is.

!!! note "TLS only"
    bomify always talks to a registry over HTTPS and has no plain-HTTP
    or skip-verify option. A registry with a self-signed certificate
    needs that certificate trusted by the OS first. For a throwaway
    local registry that sets this up for you, see
    [`deploy/registry/`](https://github.com/alejandro-velasco/bomify/tree/main/deploy/registry).

## 2. Tag the package with its destination reference

`push` publishes a package under the same local tag it's recorded
with, so that tag must be a full registry reference
(`<registry>/<repository>:<tag>`). A short tag like `myapp:1.0`
names no registry, and `push` rejects it.

Either build straight to the full reference:

```sh
bomify build sbom.json --tag registry.example.com/myapp:1.0
```

or add one to a package you've already built:

```sh
bomify tag myapp:1.0 registry.example.com/myapp:1.0
```

`bomify packages` lists every local tag, so you can confirm it's there.

## 3. Push it

```sh
bomify push registry.example.com/myapp:1.0
```

Each layer uploads with its own progress bar. Blobs the registry
already has are skipped, so pushing a new version that shares most
components with the last one uploads only what changed. Raise the
number of parallel uploads for packages with many components:

```sh
bomify push registry.example.com/myapp:1.0 --concurrency 6
```

To publish the same package under a second tag (a moving `latest`,
say), tag it and push again. Every blob is already there, so only the
new tag is written:

```sh
bomify tag registry.example.com/myapp:1.0 registry.example.com/myapp:latest
bomify push registry.example.com/myapp:latest
```

## 4. Inspect it without pulling

`bomify package manifest` prints a pushed package's SBOM manifest to
stdout without downloading any components or touching the data
directory. Use it to check what a reference contains before
committing to a full pull:

```sh
bomify package manifest registry.example.com/myapp:1.0 | jq '.components[].purl'
```

The artifact is a regular OCI artifact (type
`application/vnd.bomify.package.v1+json`), so generic tools like
`oras` or `crane` can inspect and copy it too.

## 5. Pull it somewhere else

On the machine that needs the package, log in if needed (step 1),
then:

```sh
bomify pull registry.example.com/myapp:1.0
```

This restores the manifest and every component into the data
directory and records `registry.example.com/myapp:1.0` as a local tag.
The package is then ready for `bomify distribute`, `bomify save`, or
a later `bomify push` elsewhere, exactly as if
it had been built there. Components the data directory already
holds (from an earlier build or pull) are reused when a later
`bomify build` needs them.

Pull by digest to get exactly the content you inspected, even if the
tag has since moved:

```sh
bomify pull registry.example.com/myapp@sha256:abcdef...
```

A digest pull records no local tag. Add one with `bomify tag` if you
want to refer to the package by name afterwards. `--concurrency`
works the same way as for `push`.

## 6. Log out

```sh
bomify logout registry.example.com
```

## Next steps

- [Building a package](building-a-package.md) if you don't have one
  tagged locally yet.
- [Distributing a package](distributing-a-package.md) to publish the
  pulled package's components to their own native destinations.
- [Saving packages for airgapped environments](saving-packages-for-airgapped-environments.md)
  when the target machine can't reach a registry at all.
