# syntax=docker/dockerfile:1

# The image compiles nothing: bomify and its plugins come prebuilt, static
# (CGO_ENABLED=0 for Go, musl for Rust), since the final stage is
# distroless/static, which has no libc. bomify comes from the "bomify"
# build context, a directory holding a bomify binary for this image's
# platform: CI's build job builds it, `make container-bomify` builds one
# for any machine, and a release downloads the one it published (see
# release.yml).
#
# Where the plugins come from picks the stage that installs them
# (plugins-prebuilt or plugins-release, below): "prebuilt", binaries built
# from this checkout, or "release", the plugin packages a release
# published. Only the stages the chosen one needs are built. `make
# build-container` picks "release" when CONTAINER_PLUGIN_VERSION is set.
ARG PLUGINS=prebuilt

# A shell and coreutils for the install scripts, CA certificates for the
# registry pulls a release image's install makes, and the passwd/group
# entries the final stage takes. Docker's official debian image, pulled
# from its ECR Public mirror rather than Docker Hub, whose anonymous pull
# limit CI's shared runners can hit; the two serve the same image digests.
FROM public.ecr.aws/docker/library/debian:bookworm-slim AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
COPY --from=bomify --chmod=755 bomify /usr/local/bin/bomify

# bomify only looks for plugins in <data-dir>/plugins, so each of the two
# stages below installs them into the data directory the final stage runs
# with ($HOME/.bomify, HOME being /tmp there) rather than onto PATH.

# Plugins built from this checkout, ahead of the image, as a release
# builds them: from the prebuilt-plugins build context, laid out as
# <kind>/<os>-<arch>/bomify-plugin-<kind>, holding at least this image's
# platform. `make container-plugins` builds them; CI downloads the ones
# its build-plugins job built (see .github/workflows/build.yml).
FROM base AS plugins-prebuilt

COPY --from=prebuilt-plugins . /prebuilt/

RUN mkdir -p bin \
    && cp /prebuilt/*/"linux-$(dpkg --print-architecture)"/bomify-plugin-* bin/ \
    && BOMIFY_DATA_DIR=/out/.bomify bash hack/install-plugins.sh

# The plugins a release published (see release.yml), signed keyless by
# release.yml, so `bomify plugin list` names where each came from (see
# hack/install-release-plugins.sh). PLUGIN_VERSION is the release's
# version. SIGSTORE_DIGEST pins bomify-plugin-sigstore, which nothing can
# verify before it's installed, and PLUGIN_SIGNER is the release
# workflow's identity the rest must be signed by.
FROM base AS plugins-release

ARG PLUGIN_VERSION=
ARG PLUGIN_REGISTRY=ghcr.io/alejandro-velasco/bomify/plugins
ARG SIGSTORE_DIGEST=
ARG PLUGIN_SIGNER=https://github.com/alejandro-velasco/bomify/.github/workflows/release.yml@refs/heads/main

RUN BOMIFY=/usr/local/bin/bomify BOMIFY_DATA_DIR=/out/.bomify bash hack/install-release-plugins.sh

FROM plugins-${PLUGINS} AS plugins

# distroless/static: no shell, no package manager, just the binaries below
# plus ca-certificates and tzdata (needed for the registry/HTTP(S) pulls
# bomify and its plugins make) and a /etc/passwd entry for root.
FROM gcr.io/distroless/static-debian12

# distroless only ships a passwd/group entry for root; "nobody"/"nogroup"
# (65534:65534) come from the base stage's Debian so USER below can
# resolve them.
COPY --from=plugins /etc/passwd /etc/group /etc/

# os.UserHomeDir(), which bomify's default --data-dir depends on, requires
# $HOME to be set. nobody can't write to /root, and distroless has no
# /home/nobody, but it does ship a world-writable /tmp, so that's HOME here.
ENV HOME=/tmp

COPY --from=plugins /usr/local/bin/bomify /usr/local/bin/

# The whole data directory is owned by nobody, since bomify writes
# packages alongside the plugins there (and "bomify plugin install" adds
# more). hack/install-plugins.sh symlinks bomify-plugin-docker ->
# bomify-plugin-oci, which the copy carries over as-is; a release's oci
# package installs bomify-plugin-docker itself.
COPY --from=plugins --chown=65534:65534 /out/.bomify /tmp/.bomify

USER nobody:nogroup

ENTRYPOINT ["bomify"]
