<h1 align="center">
  <img src="docsite/docs/assets/logo.svg" alt="bomify" width="320">
</h1>

`bomify` builds packages from [CycloneDX](https://cyclonedx.org/) SBOMs,
the way Docker builds images from Dockerfiles.

- `bomify build` pulls each component an SBOM describes, through a
  plugin for its type (OCI images, Helm charts, plain files, ...).
- `bomify push`/`pull` and `save`/`load` move packages through an OCI
  registry or a tarball; `bomify distribute` republishes each component
  to its own registry.
- `bomify sbom generate` builds an SBOM from a deployment medium, such as
  a Helm chart.
- `bomify security scan` scans a package's components for
  vulnerabilities, can fail on a severity threshold with VEX exemptions,
  and can gate `pull`/`load` before anything is written. Publishers can
  attach VEX to a package (`push --vex`), which a verified pull honors.
- `--sign` and `--verify` (or `bomify trust` rules) sign whole packages
  and require a trusted signature before restoring them.
- `bomify build --provenance` records SLSA build provenance, attached to
  the pushed package as a signed in-toto attestation, which `pull`/`load
  --verify-provenance` (or a `bomify trust --require-provenance` rule)
  can require.

**[Docs site](https://alejandro-velasco.github.io/bomify/)**: installation,
a quickstart, how-tos, the CLI reference, and a guide to writing plugins.

## Status

**Pre-alpha.** Flags, the data directory layout, and the plugin
contracts may change without notice.

## Build

```sh
make build
```

## Usage

Install plugins. bomify only installs plugins something vouches for, so
the first time, install `sigstore` by digest and trust bomify's release
workflow (see [Installing plugins](plugins/README.md#installing-plugins)).
Then:

```sh
bomify plugin install oci
```

Build, tag, and publish a package:

```sh
bomify login registry.example.com
bomify build path/to/bom.cdx.json --tag registry.example.com/myapp:1.0
bomify push registry.example.com/myapp:1.0
bomify pull registry.example.com/myapp:1.0
```

Move it without a registry:

```sh
bomify save registry.example.com/myapp:1.0 -o myapp.tar
bomify load -i myapp.tar
```

Sign it, and require a trusted signature to pull it:

```sh
bomify push registry.example.com/myapp:1.0 --sign sigstore --sign-option key=cosign.key
bomify pull registry.example.com/myapp:1.0 --verify sigstore --verify-option key=cosign.pub
bomify trust create sigstore --match registry.example.com --option key=cosign.pub
```

Generate an SBOM for a Helm chart, build it, and scan it with grype:

```sh
bomify sbom generate helm --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 18.11.6 > postgresql.cdx.json
bomify build postgresql.cdx.json --tag postgresql:18.11.6
bomify security scan grype postgresql:18.11.6 --fail-on high
```

Every command and flag is in [`docs/reference`](docs/reference).

## Container

[`Containerfile`](Containerfile) builds an image with `bomify` as the
entrypoint and the first-party plugins preinstalled in
`/tmp/.bomify/plugins`:

```sh
make build-container
docker run --rm -v "$PWD/testdata/helm.cdx.json:/tmp/helm.cdx.json" \
  ghcr.io/alejandro-velasco/bomify:latest build -t registry.example.com/test:1.0.0 /tmp/helm.cdx.json
```

Mounting your own data directory over `/tmp/.bomify` replaces the
preinstalled plugins; install Linux builds into it from inside the
container (`... plugin install oci`).

## Testing locally

[`deploy/registry`](deploy/registry) runs a throwaway TLS-enabled OCI
registry for testing against.

## Plugins

bomify does no fetching, publishing, scanning, or signing itself; it
hands each to a `bomify-plugin-<kind>` binary in `~/.bomify/plugins`.
[`plugins/`](plugins) holds the first-party ones, and anyone can
[publish](plugins/README.md#publishing-a-plugin) their own against the
[component](plugins/COMPONENT-CONTRACT.md),
[SBOM generation](plugins/SBOM-CONTRACT.md),
[security scanning](plugins/SECURITY-CONTRACT.md), or
[signing](plugins/SIGNING-CONTRACT.md) contracts. See
[`docs/architecture`](docs/architecture) for how it fits together.

## License

[Apache License 2.0](LICENSE).
