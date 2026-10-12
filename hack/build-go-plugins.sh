#!/usr/bin/env bash
# Builds first-party plugins written in Go (each plugins/bomify-plugin-*/
# with a go.mod, its own module; see plugins/README.md#plugin-languages)
# into OUT_DIR, laid out as hack/pluginpackages reads every plugin's
# binaries:
#
#   <OUT_DIR>/<kind>/<os>-<arch>/bomify-plugin-<kind>[.exe]
#
#   OUT_DIR     where to write them (required).
#   PLATFORMS   space-separated GOOS/GOARCH pairs to build for; this
#               machine's if unset.
#   PLUGINS     space-separated plugin directories to build; every Go
#               plugin if unset.
#
# Static (CGO_ENABLED=0) everywhere, as the container image needs.
#
#   OUT_DIR=dist/plugins hack/build-go-plugins.sh
#   OUT_DIR=dist/plugins PLATFORMS="linux/amd64 windows/amd64" PLUGINS=plugins/bomify-plugin-oci hack/build-go-plugins.sh
set -euo pipefail

: "${OUT_DIR:?OUT_DIR is required}"
platforms="${PLATFORMS:-$(go env GOOS)/$(go env GOARCH)}"
plugins="${PLUGINS:-}"
if [ -z "$plugins" ]; then
	for manifest in plugins/bomify-plugin-*/go.mod; do
		if [ -e "$manifest" ]; then
			plugins="$plugins ${manifest%/go.mod}"
		fi
	done
fi

mkdir -p "$OUT_DIR"
out_root="$(cd "$OUT_DIR" && pwd)"

for dir in $plugins; do
	if [ ! -f "$dir/go.mod" ]; then
		echo "$dir isn't a Go plugin: it has no go.mod" >&2
		exit 1
	fi
	name="$(basename "$dir")"
	kind="${name#bomify-plugin-}"
	for platform in $platforms; do
		goos="${platform%/*}"
		goarch="${platform#*/}"
		exe=""
		if [ "$goos" = windows ]; then
			exe=".exe"
		fi
		echo "==> $name $goos/$goarch"
		(cd "$dir" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -o "$out_root/$kind/$goos-$goarch/$name$exe" .)
	done
done
