---
icon: lucide/download
---

# Installation

bomify ships as a single static binary, plus one binary per first-party
plugin (see [Installing plugins](installing-plugins.md)). Pick whichever of
the following fits your workflow.

## Download a release

Every tagged release publishes a `bomify-<version>-<os>-<arch>` archive —
`.tar.gz` for Linux (amd64/arm64) and macOS (amd64/arm64), `.zip` for
Windows (amd64) — along with a `checksums.txt` covering all of them, on the
repository's [Releases](https://github.com/alejandro-velasco/bomify/releases)
page. Each archive contains `bomify` and every first-party plugin
(`bomify-plugin-oci`, `bomify-plugin-helm`, `bomify-plugin-generic`) at its
root, ready to drop onto `PATH`.

### Linux / macOS

Pick a `VERSION` from the [Releases](https://github.com/alejandro-velasco/bomify/releases)
page (e.g. `v1.11.0`), then, matching your OS/architecture:

```sh
VERSION=v1.11.0
OS=linux      # or: darwin
ARCH=amd64    # or: arm64

curl -LO "https://github.com/alejandro-velasco/bomify/releases/download/${VERSION}/bomify-${VERSION}-${OS}-${ARCH}.tar.gz"
curl -LO "https://github.com/alejandro-velasco/bomify/releases/download/${VERSION}/checksums.txt"

# Verify the download against the published checksum before running anything.
grep " bomify-${VERSION}-${OS}-${ARCH}.tar.gz\$" checksums.txt | sha256sum -c -

tar -xzf "bomify-${VERSION}-${OS}-${ARCH}.tar.gz"
chmod +x bomify bomify-plugin-*
sudo mv bomify bomify-plugin-* /usr/local/bin/
```

If you want purls using the `docker` purl type (as well as `oci`) to
resolve, add the alias `make install` also creates:

```sh
sudo ln -sf /usr/local/bin/bomify-plugin-oci /usr/local/bin/bomify-plugin-docker
```

### Windows

Download the `.zip` for your architecture from
[Releases](https://github.com/alejandro-velasco/bomify/releases), extract
it, and add the extracted folder (containing `bomify.exe` and the
`bomify-plugin-*.exe` binaries) to your `PATH`.

## Container image

[`Containerfile`](https://github.com/alejandro-velasco/bomify/blob/main/Containerfile)
builds an image with `bomify` and every first-party plugin already on
`PATH`, published to `ghcr.io/alejandro-velasco/bomify`. Its entrypoint is
`bomify`, so `docker run`/`podman run` arguments are just the CLI arguments
you'd pass locally:

```sh
docker run --rm -it \
  -v "${HOME}/.bomify:/tmp/.bomify" \
  -v "$(pwd)/sbom.json:/tmp/sbom.json" \
  --user "$(id -u):$(id -g)" \
  ghcr.io/alejandro-velasco/bomify:1.11.0 \
  build /tmp/sbom.json --tag registry.example.com/myapp:1.0
```

## Build from source

Requires [Go](https://go.dev) (see `go.mod` for the exact version this
repository targets).

```sh
git clone https://github.com/alejandro-velasco/bomify.git
cd bomify
make build      # builds ./bin/bomify
make plugins    # builds every first-party plugin into ./bin/
```

To install both onto your `PATH` (Linux/macOS, needs write access to
`/usr/local/bin`):

```sh
make install
```

This also symlinks `bomify-plugin-oci` to `bomify-plugin-docker`, so purls
using either the `oci` or `docker` purl type resolve to the same plugin.

## Verify it's working

```sh
bomify version
```
