---
icon: lucide/download
---

# Installation

bomify ships as a single static binary. Install it whichever way fits
your workflow below, then install the plugins you need with
[`bomify plugin install`](#install-plugins).

## Download a release

Every tagged release publishes a ready-to-run `bomify` binary per
platform — `bomify-<version>-<os>-<arch>` for Linux (amd64/arm64) and
macOS (amd64/arm64), `bomify-<version>-windows-amd64.exe` for Windows —
along with a `checksums.txt` covering all of them, on the repository's
[Releases](https://github.com/alejandro-velasco/bomify/releases) page.

### Linux / macOS

```sh
OS=$(uname -s | tr '[:upper:]' '[:lower:]')  # linux or darwin
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac

VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/alejandro-velasco/bomify/releases/latest | grep -oE '[^/]+$')
BINARY="bomify-${VERSION#v}-${OS}-${ARCH}"  # release tags are v-prefixed (e.g. v1.11.0), binary names aren't (bomify-1.11.0-...)

curl -LO "https://github.com/alejandro-velasco/bomify/releases/download/${VERSION}/${BINARY}"
curl -LO "https://github.com/alejandro-velasco/bomify/releases/download/${VERSION}/checksums.txt"

# Verify the download against the published checksum before running anything.
grep " ${BINARY}\$" checksums.txt | sha256sum -c -

chmod +x "${BINARY}"
sudo mv "${BINARY}" /usr/local/bin/bomify
```

### Windows

Download `bomify-<version>-windows-amd64.exe` from
[Releases](https://github.com/alejandro-velasco/bomify/releases), rename it
to `bomify.exe`, and put it in a folder on your `PATH`.

## Container image

[`Containerfile`](https://github.com/alejandro-velasco/bomify/blob/main/Containerfile)
builds an image with `bomify` on `PATH` and every first-party plugin
preinstalled in its data directory (`/tmp/.bomify/plugins`), published to
`ghcr.io/alejandro-velasco/bomify`. Its entrypoint is
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

Mounting your own data directory over `/tmp/.bomify`, as above, replaces
the preinstalled plugins with whatever is in its `plugins/` directory.
Install the plugins you need into it from inside the container, so you
get Linux builds whatever your own OS:

```sh
docker run --rm -it \
  -v "${HOME}/.bomify:/tmp/.bomify" \
  --user "$(id -u):$(id -g)" \
  ghcr.io/alejandro-velasco/bomify:1.11.0 \
  plugin install oci
```

## Build from source

Requires [Go](https://go.dev) (see `go.mod` for the exact version this
repository targets).

```sh
git clone https://github.com/alejandro-velasco/bomify.git
cd bomify
make build      # builds ./bin/bomify
```

To install it onto your `PATH` (Linux/macOS, needs write access to
`/usr/local/bin`):

```sh
sudo make install-bin
```

## Verify it's working

```sh
bomify version
```

## Install plugins

bomify delegates the real work — fetching components, generating SBOMs,
scanning, signing — to plugins, which you install separately with
`bomify plugin install`. It downloads each one as a verified package
from bomify's plugin registry and places it in `~/.bomify/plugins`, the
only place bomify looks for plugins:

```sh
bomify plugin install oci     # also installs bomify-plugin-docker
bomify plugin install helm
bomify plugin list
```

To install every first-party plugin at once:

```sh
bomify plugin install sigstore  # signing/verification
bomify plugin install oci       # container images (and bomify-plugin-docker)
bomify plugin install helm      # Helm charts, and SBOM generation for them
bomify plugin install generic   # plain HTTP downloads/uploads
bomify plugin install grype     # vulnerability scanning
```

See [Installing plugins](installing-plugins.md) for what each plugin
does, version pinning, and how verification works.
