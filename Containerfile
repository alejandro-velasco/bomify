# syntax=docker/dockerfile:1

# golang:1.27.1-bookworm rather than 1.27.0: Docker Hub only keeps the latest
# patch tag around for most variants, and 1.27.0 has already been retired
# for bookworm. go.mod's "go 1.27.0" is a minimum, so the 1.27.1 toolchain
# satisfies it.
FROM golang:1.27.1-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# CGO_ENABLED=0 is required, not just tidy: the final stage is
# distroless/static, which has no libc. A cgo-linked binary (the Go
# toolchain's default on this glibc-based builder image) would dynamically
# link against libc.so and fail to start there entirely.
ENV CGO_ENABLED=0

# bomify only looks for plugins in <data-dir>/plugins, so they're installed
# into the data directory the final stage runs with ($HOME/.bomify, HOME
# being /tmp there) rather than onto PATH.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    make install PLUGIN_DIR=/out/.bomify/plugins

# distroless/static: no shell, no package manager, just the binaries below
# plus ca-certificates and tzdata (needed for the registry/HTTP(S) pulls
# bomify and its plugins make) and a /etc/passwd entry for root.
FROM gcr.io/distroless/static-debian12

# distroless only ships a passwd/group entry for root; "nobody"/"nogroup"
# (65534:65534) come from the builder's own Debian base so USER below can
# resolve them.
COPY --from=builder /etc/passwd /etc/group /etc/

# os.UserHomeDir(), which bomify's default --data-dir depends on, requires
# $HOME to be set. nobody can't write to /root, and distroless has no
# /home/nobody, but it does ship a world-writable /tmp, so that's HOME here.
ENV HOME=/tmp

COPY --from=builder /usr/local/bin/bomify /usr/local/bin/

# The whole data directory is owned by nobody, since bomify writes
# packages alongside the plugins there (and "bomify plugin install" adds
# more). make install also symlinks bomify-plugin-docker ->
# bomify-plugin-oci, which the copy carries over as-is.
COPY --from=builder --chown=65534:65534 /out/.bomify /tmp/.bomify

USER nobody:nogroup

ENTRYPOINT ["bomify"]
