#!/usr/bin/env bash
# Cross-compiles bomify for each platform in RELEASE_PLATFORMS as a bare,
# ready-to-run binary per platform —
# DIST_DIR/bomify-<version>-<os>-<arch>[.exe] — alongside a checksums.txt
# covering all of them. Invoked by `make dist`, which supplies VERSION,
# LDFLAGS, DIST_DIR and RELEASE_PLATFORMS as environment variables.
#
# Plugins aren't part of a release: they're published as plugin packages
# instead (see hack/pluginpackages), for users to install with
# `bomify plugin install`.
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${LDFLAGS:?LDFLAGS is required}"
: "${DIST_DIR:?DIST_DIR is required}"
: "${RELEASE_PLATFORMS:?RELEASE_PLATFORMS is required}"

mkdir -p "$DIST_DIR"
dist_dir="$(cd "$DIST_DIR" && pwd)"

for platform in $RELEASE_PLATFORMS; do
	os=${platform%/*}
	arch=${platform#*/}
	echo "==> $os/$arch"

	ext=""
	[ "$os" = "windows" ] && ext=".exe"

	GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$dist_dir/bomify-$VERSION-$os-$arch$ext" .
done

(cd "$dist_dir" && sha256sum -- bomify-* > checksums.txt)
