#!/usr/bin/env bash
# Cross-compiles bomify and its plugins for each platform in
# RELEASE_PLATFORMS and packages them into per-platform archives under
# DIST_DIR, alongside a checksums.txt covering all of them. Invoked by
# `make dist`, which supplies VERSION, LDFLAGS, DIST_DIR and
# RELEASE_PLATFORMS as environment variables.
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${LDFLAGS:?LDFLAGS is required}"
: "${DIST_DIR:?DIST_DIR is required}"
: "${RELEASE_PLATFORMS:?RELEASE_PLATFORMS is required}"

build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

mkdir -p "$DIST_DIR"
dist_dir="$(cd "$DIST_DIR" && pwd)"

for platform in $RELEASE_PLATFORMS; do
	os=${platform%/*}
	arch=${platform#*/}
	out="$build_dir/$os-$arch"
	mkdir -p "$out"
	echo "==> $os/$arch"

	ext=""
	[ "$os" = "windows" ] && ext=".exe"

	GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$out/bomify$ext" .
	GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -o "$out/" ./plugins/...

	archive="$dist_dir/bomify-$VERSION-$os-$arch"
	if [ "$os" = "windows" ]; then
		(cd "$out" && zip -qr "$archive.zip" .)
	else
		tar -czf "$archive.tar.gz" -C "$out" .
	fi
done

(cd "$dist_dir" && sha256sum -- * > checksums.txt)
