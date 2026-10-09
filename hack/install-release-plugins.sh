#!/usr/bin/env bash
# Installs the first-party plugins a bomify release published into
# DATA_DIR the way a user would (see plugins/README.md#installing-plugins),
# so `bomify plugin list` names each one's version and the signed package
# it came from: bomify-plugin-sigstore pinned to SIGSTORE_DIGEST, its
# line's digest in the release's plugin-digests.txt; then a trust rule
# for PLUGIN_SIGNER, the release workflow's identity, over
# PLUGIN_REGISTRY; then every other plugin under plugins/ at
# PLUGIN_VERSION, verified against that rule. The rule stays in DATA_DIR,
# so later installs from PLUGIN_REGISTRY are verified too.
#
# Run from the repository root by the Containerfile, for a release image.
set -euo pipefail

: "${BOMIFY:?BOMIFY is required}"
: "${DATA_DIR:?DATA_DIR is required}"
: "${PLUGIN_VERSION:?PLUGIN_VERSION is required}"
: "${PLUGIN_REGISTRY:?PLUGIN_REGISTRY is required}"
: "${SIGSTORE_DIGEST:?SIGSTORE_DIGEST is required}"
: "${PLUGIN_SIGNER:?PLUGIN_SIGNER is required}"

bomify() {
	"$BOMIFY" --data-dir "$DATA_DIR" "$@"
}

bomify plugin install "sigstore@$SIGSTORE_DIGEST" --registry "$PLUGIN_REGISTRY"
bomify trust create sigstore --match "$PLUGIN_REGISTRY" \
	--option "certificate-identity=$PLUGIN_SIGNER" \
	--option certificate-oidc-issuer=https://token.actions.githubusercontent.com

for dir in plugins/bomify-plugin-*/; do
	kind="${dir#plugins/bomify-plugin-}"
	kind="${kind%/}"
	if [ "$kind" != sigstore ]; then
		bomify plugin install "$kind:$PLUGIN_VERSION" --registry "$PLUGIN_REGISTRY"
	fi
done

bomify plugin list
