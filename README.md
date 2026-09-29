<h1 align="center">
  <img src="docsite/docs/assets/logo.svg" alt="bomify" width="320">
</h1>

`bomify` is a CLI that builds packages from [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOMs).

Give it an SBOM and `bomify build` walks its components, delegating each one to an external plugin binary that knows how to pull it; `bomify distribute` later republishes an already-built package the same way, one component at a time. `bomify sbom generate` goes the other direction — inspecting a deployment medium (a Helm chart, an OCI image, ...) through its own plugin to produce a fresh SBOM in the first place. `bomify security scan` scans a built package for vulnerabilities, calling a scanning-tool plugin (e.g. grype) once per component — concurrently, the same way `build`/`distribute` do — and storing one vulnerability report per component, shared by every package that includes it. `bomify push --sign`/`bomify pull --verify` sign a whole package and require a trusted signature before restoring it, through a signing plugin (e.g. sigstore).

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

Sign a package as you push (or save) it, and refuse to pull (or load) it unless a trusted signature verifies — per pull with `--verify`, or for every package under a prefix with a `bomify trust` rule:

```sh
bomify push registry.example.com/myapp:1.0 --sign sigstore --sign-option key=cosign.key
bomify pull registry.example.com/myapp:1.0 --verify sigstore --verify-option key=cosign.pub
bomify trust create sigstore --match registry.example.com --option key=cosign.pub
```

Remove a package once you're done with it, and log out:

```sh
bomify package remove registry.example.com/myapp:1.0   # or: bomify rmp registry.example.com/myapp:1.0
bomify logout registry.example.com
```

See [`docs/reference`](docs/reference) for the full CLI reference, covering every command and flag (regenerate it with `make docs` after changing a command).

Generate an SBOM for a Helm chart, rather than starting from one:

```sh
bomify sbom generate helm --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 18.11.6 > postgresql.cdx.json
```

Build it, then scan the package's components for known vulnerabilities with [grype](https://github.com/anchore/grype) — each component's report lands under `<data-dir>/vulnerabilities/`, and `bomify package vulnerabilities` prints them back out:

```sh
bomify build postgresql.cdx.json --tag postgresql:18.11.6
bomify security scan grype postgresql:18.11.6
bomify package vulnerabilities postgresql:18.11.6
```

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

Neither `bomify build` nor `bomify distribute` build or publish anything themselves — they detect a "kind" for each SBOM component and delegate to an external `bomify-plugin-<kind>` binary on `PATH`. `bomify sbom generate <medium>` delegates the same way, to that binary's own `sbom generate` subcommand; `bomify security scan <type>` does too, but per component — the same plugin, called once per component in a built package, concurrently; and `--sign <kind>`/`--verify <kind>` hand a whole package's signature to that binary's `signature` subcommands. [`plugins/`](plugins) holds the plugins bomify ships itself (see [`plugins/README.md`](plugins/README.md)); anyone can write and install their own third-party plugin for a kind bomify doesn't support.

See [ARCHITECTURE.md](ARCHITECTURE.md) for how plugin dispatch works, and [`plugins/COMPONENT-CONTRACT.md`](plugins/COMPONENT-CONTRACT.md) (component plugins), [`plugins/SBOM-CONTRACT.md`](plugins/SBOM-CONTRACT.md) (SBOM generation plugins), [`plugins/SECURITY-CONTRACT.md`](plugins/SECURITY-CONTRACT.md) (security scanning plugins), and [`plugins/SIGNING-CONTRACT.md`](plugins/SIGNING-CONTRACT.md) (signing plugins) for the four independent contracts a plugin can implement.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) for the full text.
