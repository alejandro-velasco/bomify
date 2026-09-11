# bomify

`bomify` is a CLI that builds packages from [CycloneDX](https://cyclonedx.org/) Software Bills of Materials (SBOMs).

Give it an SBOM and it will build a package for each component it describes.

## Status

Early scaffolding. SBOM parsing (JSON and XML) works; package generation is not implemented yet.

## Build

```sh
go build -o bin/bomify .
# or
make build
```

## Usage

```sh
bomify build --input path/to/bom.cdx.json --output dist/
```

| Flag              | Description                                  | Default |
|-------------------|-----------------------------------------------|---------|
| `-i, --input`     | Path to the CycloneDX SBOM file (required)     | -       |
| `-o, --output`    | Directory to write built packages to           | `dist`  |
| `-v, --verbose`   | Enable verbose output                          | `false` |

## Development

```sh
make test   # run tests
make build  # build the binary
make tidy   # tidy go.mod/go.sum
```

## Project layout

```
main.go              entrypoint
cmd/                  CLI commands (cobra)
internal/sbom/        CycloneDX SBOM loading and inspection
testdata/             sample SBOMs used by tests
```
