# bomify

`bomify` is a CLI that builds packages from [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOMs).

Give it an SBOM and `bomify build`/`bomify mirror` walk its components and delegate each one to an external plugin binary that knows how to pull or push it.

## Status

Early Development

## Build

```sh
make build
```

## Usage

```sh
bomify build  --file path/to/bom.cdx.json --output dist/
bomify mirror --file path/to/bom.cdx.json --remote registry.example.com/mirror
```

## Plugins

Neither `bomify build` nor `bomify mirror` build or publish anything
themselves — they detect a "kind" for each SBOM component and delegate to an
external `bomify-plugin-<kind>` binary on `PATH`.

[`plugins/`](plugins) holds the plugins bomify creates and supports itself
(see [`plugins/README.md`](plugins/README.md) for the list), starting with
[`bomify-plugin-oci`](plugins/bomify-plugin-oci), which pulls and pushes
container images using [crane](https://github.com/google/go-containerregistry).
Anyone can also write and install their own third-party
`bomify-plugin-<kind>` binary for a kind bomify doesn't ship.

The kind is taken directly from the component's purl type (parsed with
[package-url/packageurl-go](https://github.com/package-url/packageurl-go)):
a component with purl `pkg:oci/nginx@1.27` has kind `oci` and needs a
`bomify-plugin-oci` binary; `pkg:npm/left-pad@1.3.0` needs `bomify-plugin-npm`;
`pkg:docker/postgres@16` needs `bomify-plugin-docker`. A component with no
purl, or an unparseable one, makes the whole run fail immediately.

Each plugin must implement two subcommands:

```sh
bomify-plugin-<kind> pull --component '<JSON-encoded CycloneDX component>' --output <dir>
bomify-plugin-<kind> push --component '<JSON-encoded CycloneDX component>' --remote <endpoint>
```

`bomify build` invokes `pull`, which should fetch or build the component and
write it into the local directory `dir` (bomify's `--output`, default
`dist`). `bomify mirror` invokes `push`, which should publish the component
directly to `remote` (bomify's `--remote`).

For either subcommand, the plugin must print a single JSON object to stdout
on success and exit 0:

```json
{ "outputPath": "path/to/artifact/or/remote/ref", "message": "optional human-readable summary" }
```
