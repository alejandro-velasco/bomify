#!/usr/bin/env bash
# Builds and pushes one bomify plugin package per SBOM that
# hack/pluginpackages wrote under PACKAGES_DIR, as
# $PLUGIN_REGISTRY/<kind>:$VERSION — plus :latest when VERSION is a plain
# release version (e.g. 1.12.0), never for a dev build. Invoked by
# `make push-plugin-packages`, which supplies BOMIFY, VERSION,
# PACKAGES_DIR, and PLUGIN_REGISTRY.
#
# Uses a throwaway data directory, so nothing here touches (or depends
# on) the caller's own ~/.bomify. Registry credentials are the ones
# `bomify login` (or `docker login` — they share a store) already has.
#
# If PLUGIN_SIGN_KEY is set, every package is signed with
# bomify-plugin-sigstore using that private key: the sigstore binary
# built for this machine is installed into the throwaway data directory
# first, since that's the only place bomify looks for it.
set -euo pipefail

: "${BOMIFY:?BOMIFY is required}"
: "${VERSION:?VERSION is required}"
: "${PACKAGES_DIR:?PACKAGES_DIR is required}"
: "${PLUGIN_REGISTRY:?PLUGIN_REGISTRY is required}"

data_dir="$(mktemp -d)"
trap 'rm -rf "$data_dir"' EXIT

bomify() {
	"$BOMIFY" --data-dir "$data_dir" "$@"
}

sign_args=()
if [ -n "${PLUGIN_SIGN_KEY:-}" ]; then
	host_os=$(go env GOOS)
	host_arch=$(go env GOARCH)
	ext=""
	[ "$host_os" = "windows" ] && ext=".exe"
	sigstore="$PACKAGES_DIR/sigstore/$host_os-$host_arch/bomify-plugin-sigstore$ext"
	if [ ! -f "$sigstore" ]; then
		echo "PLUGIN_SIGN_KEY is set, but $sigstore wasn't built (is $host_os/$host_arch in RELEASE_PLATFORMS?)" >&2
		exit 1
	fi
	mkdir -p "$data_dir/plugins"
	cp "$sigstore" "$data_dir/plugins/"
	sign_args=(--sign sigstore --sign-option "key=$PLUGIN_SIGN_KEY")
fi

shopt -s nullglob
sboms=("$PACKAGES_DIR"/*/sbom.cdx.json)
if [ ${#sboms[@]} -eq 0 ]; then
	echo "no plugin package SBOMs under $PACKAGES_DIR (run \`make plugin-packages\` first)" >&2
	exit 1
fi

tags=("$VERSION")
if [[ "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	tags+=(latest)
fi

for sbom in "${sboms[@]}"; do
	kind=$(basename "$(dirname "$sbom")")
	repo="$PLUGIN_REGISTRY/$kind"
	echo "==> $repo (${tags[*]})"

	tag_args=()
	for tag in "${tags[@]}"; do
		tag_args+=(--tag "$repo:$tag")
	done
	bomify build "$sbom" "${tag_args[@]}"

	for tag in "${tags[@]}"; do
		bomify push "$repo:$tag" "${sign_args[@]}"
	done
done
