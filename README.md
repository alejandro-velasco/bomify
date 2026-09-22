# bomify

`bomify` is a CLI that builds packages from [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOMs).

Give it an SBOM and `bomify build` walks its components, delegating each one to an external plugin binary that knows how to pull it; `bomify distribute` later republishes an already-built package the same way, one component at a time.

**[Docs site](https://alejandro-velasco.github.io/bomify/)** — installation, a guided quickstart, the full CLI reference, and a guide to building a plugin.

## Status

**Pre-Alpha.** bomify is under active early development. Its CLI flags, data
directory layout, and plugin contract can all still change without notice,
and there is currently no guarantee of stability or backward compatibility
between versions. This will change as the project matures.

## Build

```sh
make build
```

## Usage

Log in to a registry (default `docker.io`), then build a package from an SBOM and tag it:

```sh
bomify login registry.example.com
bomify build path/to/bom.cdx.json --tag registry.example.com/myapp:1.0
bomify tag registry.example.com/myapp:1.0 registry.example.com/myapp:latest
```

Push the built package to the registry, or pull one that's already there:

```sh
bomify push registry.example.com/myapp:1.0
bomify pull registry.example.com/myapp:1.0
```

Save one or more tagged packages to a tarball, and load it back on another machine — no registry needed:

```sh
bomify save registry.example.com/myapp:1.0 -o myapp.tar
bomify load -i myapp.tar
```

Remove a package once you're done with it, and log out:

```sh
bomify package remove registry.example.com/myapp:1.0   # or: bomify rmp registry.example.com/myapp:1.0
bomify logout registry.example.com
```

See [`docs/reference`](docs/reference) for the full CLI reference, covering every command and flag (regenerate it with `make docs` after changing a command).

## Container

[`Containerfile`](Containerfile) builds an image with `bomify` and its first-party plugins on `PATH`:

```sh
make build-container
```

Its entrypoint is `bomify`, so `docker run`/`podman run` arguments are just the CLI arguments you'd pass locally:

```sh
docker run -v "${HOME}/.bomify:/tmp/.bomify" -v `pwd`/testdata/helm.cdx.json:/tmp/helm.cdx.json --rm --user $(id -u):$(id -g) -it ghcr.io/alejandro-velasco/bomify:latest build -t registry.com/container-test:1.0.0 /tmp/helm.cdx.json
```

## Testing locally

[`deploy/registry/`](deploy/registry) spins up a throwaway, TLS-enabled OCI registry (self-signed cert generated and trusted for you) for exercising `build`/`distribute`/`pull` against a real registry without needing an account anywhere — see its [README](deploy/registry/README.md).

## Plugins

Neither `bomify build` nor `bomify distribute` build or publish anything themselves — they detect a "kind" for each SBOM component and delegate to an external `bomify-plugin-<kind>` binary on `PATH`. [`plugins/`](plugins) holds the plugins bomify ships itself (see [`plugins/README.md`](plugins/README.md)); anyone can write and install their own third-party plugin for a kind bomify doesn't support.

See [ARCHITECTURE.md](ARCHITECTURE.md) for how plugin dispatch, the pull/push/remote contract, and result reporting work.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) for the full text.
