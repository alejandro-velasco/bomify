# bomify

`bomify` is a CLI that builds packages from [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOMs).

Give it an SBOM and `bomify package` walks its components and delegates each one to an external plugin binary that knows how to build it.

## Status

Early Development

## Build

```sh
make build
```

## Usage

```sh
bomify package --sbom path/to/bom.cdx.json --output dist/
```

## Plugins

`bomify package` doesn't build anything itself — it detects a "kind" for each
SBOM component and delegates to an external `bomify-build-<kind>` binary on
`PATH`.

The kind is taken directly from the component's purl type (parsed with
[package-url/packageurl-go](https://github.com/package-url/packageurl-go)):
a component with purl `pkg:oci/nginx@1.27` has kind `oci` and needs a
`bomify-build-oci` binary; `pkg:npm/left-pad@1.3.0` needs `bomify-build-npm`;
`pkg:docker/postgres@16` needs `bomify-build-docker`. A component with no
purl, or an unparseable one, makes the whole `package` run fail immediately.

For a given kind, bomify runs the plugin as:

```sh
bomify-build-<kind> --component '<JSON-encoded CycloneDX component>' --output <output-dir>
```

The plugin must print a single JSON object to stdout on success and exit 0:

```json
{ "outputPath": "path/to/artifact", "message": "optional human-readable summary" }
```
