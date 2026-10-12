#!/usr/bin/env bash
# Builds first-party plugins written in Rust (each plugins/bomify-plugin-*/
# with a Cargo.toml; see plugins/README.md#plugin-languages) into OUT_DIR,
# laid out as hack/pluginpackages reads every plugin's binaries:
#
#   <OUT_DIR>/<kind>/<os>-<arch>/bomify-plugin-<kind>[.exe]
#
#   OUT_DIR     where to write them (required).
#   PLATFORMS   space-separated GOOS/GOARCH-style pairs to build for, as a
#               release does: statically, against musl on Linux (the
#               container image has no libc; needs musl-tools) and with
#               the C runtime linked in on Windows. Unset, the plugins are
#               built for this machine, its usual way.
#   PLUGINS     space-separated plugin directories to build; every Rust
#               plugin if unset.
#
# Each crate's rust-toolchain.toml pins the toolchain rustup installs.
# Unlike Go, Rust can't cross-compile to every platform from one machine,
# since its TLS stack compiles C: a release builds each platform on its
# own runner (see .github/workflows/plugins.yml). CARGO_TARGET_DIR, if
# set, is where cargo builds, as for cargo itself.
#
#   OUT_DIR=dist/plugins hack/build-rust-plugins.sh
#   OUT_DIR=dist/plugins PLATFORMS=linux/amd64 hack/build-rust-plugins.sh
set -euo pipefail

: "${OUT_DIR:?OUT_DIR is required}"
plugins="${PLUGINS:-}"
if [ -z "$plugins" ]; then
	for manifest in plugins/bomify-plugin-*/Cargo.toml; do
		if [ -e "$manifest" ]; then
			plugins="$plugins ${manifest%/Cargo.toml}"
		fi
	done
fi

mkdir -p "$OUT_DIR"
out_root="$(cd "$OUT_DIR" && pwd)"

# target_of prints the target triple a release builds a platform with.
target_of() {
	case "$1" in
	linux/amd64) echo x86_64-unknown-linux-musl ;;
	linux/arm64) echo aarch64-unknown-linux-musl ;;
	darwin/amd64) echo x86_64-apple-darwin ;;
	darwin/arm64) echo aarch64-apple-darwin ;;
	windows/amd64) echo x86_64-pc-windows-msvc ;;
	windows/arm64) echo aarch64-pc-windows-msvc ;;
	*)
		echo "no Rust target for platform $1" >&2
		return 1
		;;
	esac
}

# platform_of prints the platform, as GOOS/GOARCH, a target triple builds
# for.
platform_of() {
	local os arch
	case "$1" in
	*-linux-*) os=linux ;;
	*-apple-darwin) os=darwin ;;
	*-windows-*) os=windows ;;
	*)
		echo "no platform for Rust target $1" >&2
		return 1
		;;
	esac
	case "$1" in
	x86_64-*) arch=amd64 ;;
	aarch64-*) arch=arm64 ;;
	*)
		echo "no platform for Rust target $1" >&2
		return 1
		;;
	esac
	echo "$os/$arch"
}

# build builds the crate in dir, for target if set, else for this
# machine, and copies its binary into the layout.
build() {
	local dir="$1" target="$2" platform name kind exe built
	name="$(basename "$dir")"
	kind="${name#bomify-plugin-}"
	if [ -n "$target" ]; then
		platform="$(platform_of "$target")"
	else
		platform="$(platform_of "$(cd "$dir" && rustc -vV | sed -n 's/^host: //p')")"
	fi
	exe=""
	if [ "${platform%/*}" = windows ]; then
		exe=".exe"
	fi
	echo "==> $name $platform"

	(
		cd "$dir"
		if [ -n "$target" ]; then
			rustup target add "$target"
			if [ "${platform%/*}" = windows ]; then
				export RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+crt-static"
			fi
			cargo build --release --locked --target "$target"
		else
			cargo build --release --locked
		fi
	)

	built="${CARGO_TARGET_DIR:-$dir/target}/${target:+$target/}release/$name$exe"
	mkdir -p "$out_root/$kind/${platform%/*}-${platform#*/}"
	cp "$built" "$out_root/$kind/${platform%/*}-${platform#*/}/"
}

for dir in $plugins; do
	if [ ! -f "$dir/Cargo.toml" ]; then
		echo "$dir isn't a Rust plugin: it has no Cargo.toml" >&2
		exit 1
	fi
	if [ -z "${PLATFORMS:-}" ]; then
		build "$dir" ""
		continue
	fi
	for platform in $PLATFORMS; do
		build "$dir" "$(target_of "$platform")"
	done
done
