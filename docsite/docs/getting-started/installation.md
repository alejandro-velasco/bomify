---
icon: lucide/download
---

# Installation

bomify is a single static binary. Install it, then
[install the plugins](#install-plugins) you need.

## Download a release

Each [release](https://github.com/alejandro-velasco/bomify/releases)
publishes `bomify-<version>-<os>-<arch>` for Linux and macOS (amd64,
arm64) and `bomify-<version>-windows-amd64.exe`, plus `checksums.txt`.

### Linux / macOS

```sh
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m); case "$ARCH" in x86_64) ARCH=amd64 ;; aarch64) ARCH=arm64 ;; esac
VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/alejandro-velasco/bomify/releases/latest | grep -oE '[^/]+$')
BINARY="bomify-${VERSION#v}-${OS}-${ARCH}"   # tags are v-prefixed; binary names aren't

curl -LO "https://github.com/alejandro-velasco/bomify/releases/download/${VERSION}/${BINARY}"
curl -LO "https://github.com/alejandro-velasco/bomify/releases/download/${VERSION}/checksums.txt"
grep " ${BINARY}\$" checksums.txt | sha256sum -c -

chmod +x "${BINARY}" && sudo mv "${BINARY}" /usr/local/bin/bomify
```

### Windows

Download `bomify-<version>-windows-amd64.exe`, rename it `bomify.exe`,
and put it on your `PATH`.

## Container image

`ghcr.io/alejandro-velasco/bomify` has `bomify` as its entrypoint and
every first-party plugin preinstalled in `/tmp/.bomify/plugins`: its
release's signed plugin packages, installed as
[Installing plugins](installing-plugins.md) describes, with the trust
rule for bomify's release workflow, so `bomify plugin list` names where
each came from:

```sh
docker run --rm -it \
  -v "${HOME}/.bomify:/tmp/.bomify" -v "$(pwd)/sbom.json:/tmp/sbom.json" \
  --user "$(id -u):$(id -g)" \
  ghcr.io/alejandro-velasco/bomify:1.11.0 build /tmp/sbom.json --tag registry.example.com/myapp:1.0
```

Mounting your own data directory, as above, replaces the preinstalled
plugins. Install Linux builds into it from inside the container (`...
plugin install oci`).

## Build from source

Requires [Go](https://go.dev) (version in `go.mod`):

```sh
git clone https://github.com/alejandro-velasco/bomify.git && cd bomify
make build              # ./bin/bomify
sudo make install-bin   # onto PATH
bomify version
```

## Install plugins

Plugins do the real work: fetching components, generating SBOMs,
scanning, and signing. `bomify plugin install` downloads them into
`~/.bomify/plugins` and refuses anything nothing vouches for, so the
first install takes two steps:

1. **Install `sigstore` by digest.** It verifies every other plugin, so
   nothing can verify it yet. Use its line from `plugin-digests.txt` on
   your [release](https://github.com/alejandro-velasco/bomify/releases):

    ```sh
    bomify plugin install sigstore@sha256:<digest>
    ```

2. **Trust bomify's release workflow, then install the rest:**

    ```sh
    bomify trust create sigstore --match ghcr.io/alejandro-velasco/bomify/plugins \
      --option certificate-identity=https://github.com/alejandro-velasco/bomify/.github/workflows/release.yml@refs/heads/main \
      --option certificate-oidc-issuer=https://token.actions.githubusercontent.com

    bomify plugin install oci       # container images
    bomify plugin install helm      # Helm charts, and SBOMs for them
    bomify plugin install generic   # plain HTTP files
    bomify plugin install grype     # vulnerability scanning
    bomify plugin list
    ```

For a throwaway test environment only, `--verify=false` skips both steps.

!!! warning "Unverified plugins run with your permissions"
    `--verify=false` installs whatever the registry serves. Anyone who can
    publish to it, or tamper with it, can run code as you.

See [Installing plugins](installing-plugins.md) for versions and how
verification works.
