#!/usr/bin/env bash
# Builds and pushes one bomify plugin package per SBOM that
# hack/pluginpackages wrote under PACKAGES_DIR, as
# $PLUGIN_REGISTRY/<kind>:$VERSION — plus :latest when VERSION is a plain
# release version (e.g. 1.12.0), never for a dev build. Invoked by
# `make push-plugin-packages`, which supplies BOMIFY, VERSION,
# PACKAGES_DIR, and PLUGIN_REGISTRY. Each package's pinned reference
# (<repository>@<digest>) is written to PLUGIN_DIGESTS_FILE (default
# PACKAGES_DIR/plugin-digests.txt), for the release to publish.
#
# Every package is built with --provenance, so it's pushed with SLSA
# build provenance attached, signed along with the package when signing
# is set up below. Export BOMIFY_INVOCATION_ID (e.g. the CI run's URL) to
# record which run built it.
#
# Uses a throwaway data directory, so nothing here touches the caller's
# own ~/.bomify (or $BOMIFY_DATA_DIR). The one thing it takes from there
# is conf/auth.json, so registry credentials are the ones `bomify login`
# already has, falling back to `docker login`'s.
#
# Every package is signed with bomify-plugin-sigstore when either is set:
#
#   PLUGIN_SIGN_KEYLESS=true  keyless: a short-lived Sigstore certificate
#                             for an OIDC identity token. In GitHub Actions
#                             (with `permissions: id-token: write`) this
#                             script requests a fresh token for the
#                             workflow itself right before every push —
#                             tokens only last minutes, far less than a
#                             whole release — so packages are signed as
#                             the workflow itself. Elsewhere it signs with the
#                             SIGSTORE_ID_TOKEN you export (e.g. for local
#                             testing), refusing one about to expire.
#   PLUGIN_SIGN_KEY=<path>    with that private key instead.
#
# Either way the sigstore binary built for this machine is installed into
# the throwaway data directory first, since that's the only place bomify
# looks for it.
set -euo pipefail

: "${BOMIFY:?BOMIFY is required}"
: "${VERSION:?VERSION is required}"
: "${PACKAGES_DIR:?PACKAGES_DIR is required}"
: "${PLUGIN_REGISTRY:?PLUGIN_REGISTRY is required}"

HACK_DIR="$(dirname "$0")"
. "$HACK_DIR/common.sh"

data_dir="$(mktemp -d)"
trap 'rm -rf "$data_dir"' EXIT
# Versioned before anything goes in, or bomify would refuse it.
init_data_dir "$data_dir"

caller_auth="${BOMIFY_DATA_DIR:-$HOME/.bomify}/conf/auth.json"
if [ -f "$caller_auth" ]; then
	mkdir -p "$data_dir/conf"
	cp "$caller_auth" "$data_dir/conf/auth.json"
fi

bomify() {
	"$BOMIFY" --data-dir "$data_dir" "$@"
}

# min_token_ttl is how many seconds a keyless identity token must still be
# valid for when a push starts: the token is only used once the package
# has finished uploading. PLUGIN_SIGN_MIN_TOKEN_TTL lowers it for a
# short-lived token you supplied yourself, e.g. for local testing.
min_token_ttl=${PLUGIN_SIGN_MIN_TOKEN_TTL:-120}

# github_id_token prints a fresh Sigstore-audience OIDC token for this
# GitHub Actions job.
github_id_token() {
	curl -fsSL -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
		"$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | jq -er .value
}

# token_ttl prints how many seconds the JWT $1 has left before it expires
# (negative once it has), from its own exp claim. It doesn't check the
# token is genuine — Fulcio does that when it's used — only that it isn't
# stale.
token_ttl() {
	local payload
	payload=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
	# JWTs use unpadded base64url; restore the padding base64 -d needs.
	case $((${#payload} % 4)) in
	2) payload="$payload==" ;;
	3) payload="$payload=" ;;
	esac
	echo $(($(printf '%s' "$payload" | base64 -d | jq -er .exp) - $(date +%s)))
}

# refresh_identity_token exports the SIGSTORE_ID_TOKEN the next keyless
# signature uses — fresh from GitHub Actions when running there — failing
# if it's missing or about to expire.
refresh_identity_token() {
	if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
		if ! SIGSTORE_ID_TOKEN=$(github_id_token); then
			echo "couldn't get an identity token from GitHub Actions" >&2
			return 1
		fi
		export SIGSTORE_ID_TOKEN
	fi
	if [ -z "${SIGSTORE_ID_TOKEN:-}" ]; then
		echo "keyless signing needs an identity token: run in GitHub Actions with \`permissions: id-token: write\`, or export SIGSTORE_ID_TOKEN" >&2
		return 1
	fi

	local ttl
	ttl=$(token_ttl "$SIGSTORE_ID_TOKEN")
	if [ "$ttl" -lt "$min_token_ttl" ]; then
		echo "the identity token expires in ${ttl}s, less than the ${min_token_ttl}s a push needs; export a fresh SIGSTORE_ID_TOKEN" >&2
		return 1
	fi
	echo "    signing keyless (identity token valid for ${ttl}s)"
}

keyless=false
sign_args=()
if [ "${PLUGIN_SIGN_KEYLESS:-}" = "true" ] && [ -n "${PLUGIN_SIGN_KEY:-}" ]; then
	echo "set PLUGIN_SIGN_KEYLESS=true or PLUGIN_SIGN_KEY, not both" >&2
	exit 1
elif [ "${PLUGIN_SIGN_KEYLESS:-}" = "true" ]; then
	for tool in curl jq; do
		command -v "$tool" >/dev/null || { echo "keyless signing needs $tool" >&2; exit 1; }
	done
	keyless=true
	sign_args=(--sign sigstore)
elif [ -n "${PLUGIN_SIGN_KEY:-}" ]; then
	sign_args=(--sign sigstore --sign-option "key=$PLUGIN_SIGN_KEY")
fi

if [ ${#sign_args[@]} -gt 0 ]; then
	host_os=$(go env GOOS)
	host_arch=$(go env GOARCH)
	ext=""
	[ "$host_os" = "windows" ] && ext=".exe"
	sigstore="$PACKAGES_DIR/sigstore/$host_os-$host_arch/bomify-plugin-sigstore$ext"
	if [ ! -f "$sigstore" ]; then
		echo "signing needs $sigstore, which wasn't built (is $host_os/$host_arch in RELEASE_PLATFORMS?)" >&2
		exit 1
	fi
	mkdir -p "$data_dir/plugins"
	cp "$sigstore" "$data_dir/plugins/"
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

# Every package pushed, pinned by digest, one "<repository>@<digest>" per
# line: the release publishes this so users can bootstrap
# bomify-plugin-sigstore — which has nothing yet to verify its signature —
# from a pin that didn't come from the registry itself.
digests_file=${PLUGIN_DIGESTS_FILE:-$PACKAGES_DIR/plugin-digests.txt}
: >"$digests_file"

for sbom in "${sboms[@]}"; do
	kind=$(basename "$(dirname "$sbom")")
	repo="$PLUGIN_REGISTRY/$kind"
	echo "==> $repo (${tags[*]})"

	tag_args=()
	for tag in "${tags[@]}"; do
		tag_args+=(--tag "$repo:$tag")
	done
	bomify build "$sbom" "${tag_args[@]}" --provenance

	for tag in "${tags[@]}"; do
		if [ "$keyless" = true ]; then
			refresh_identity_token
		fi
		# --quiet prints just <repository>@<digest> for what was pushed
		# (and signed) — never re-resolved from the tag afterwards.
		pinned=$(bomify push "$repo:$tag" "${sign_args[@]}" --quiet)
		echo "    pushed $pinned"
		if [ "$tag" = "$VERSION" ]; then
			echo "$pinned" >>"$digests_file"
		fi
	done
done

echo "==> pinned references written to $digests_file"
cat "$digests_file"
