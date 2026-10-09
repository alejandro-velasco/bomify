#!/usr/bin/env bash
# Installs the first-party plugins `make plugins` built under bin/ into
# BOMIFY_DATA_DIR's plugins directory, the only place bomify looks for
# them, starting the data directory, versioned, if it's new (see
# common.sh's init_data_dir).
#
# Run from the repository root by `make install-plugins`.
set -euo pipefail

: "${BOMIFY_DATA_DIR:?BOMIFY_DATA_DIR is required}"

HACK_DIR="$(dirname "$0")"
. "$HACK_DIR/common.sh"

plugin_dir="$BOMIFY_DATA_DIR/plugins"

init_data_dir "$BOMIFY_DATA_DIR"
install -d "$plugin_dir"
install -m755 bin/bomify-plugin-* "$plugin_dir/"
# Alias bomify-plugin-oci to bomify-plugin-docker for backward compatibility
ln -sf bomify-plugin-oci "$plugin_dir/bomify-plugin-docker"
