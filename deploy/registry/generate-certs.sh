#!/usr/bin/env bash
set -euo pipefail

# Generates a self-signed TLS certificate and key for the local test
# registry, valid for "localhost" (bomify running on the host, talking to
# the registry's published port) and "registry" (bomify running in another
# container on the same docker network, talking to this one by name), then
# trusts it system-wide so bomify (and crane/oras/helm under the hood, and
# `docker`/`podman push`) accept it without any "skip verification" flag —
# bomify doesn't have one, by design.
#
# Idempotent: does nothing (including no re-trust attempt) if
# certs/registry.crt and certs/registry.key already exist, unless --force
# is passed.

cd "$(dirname "${BASH_SOURCE[0]}")"

force=false
if [[ "${1:-}" == "--force" ]]; then
  force=true
fi

cert_dir="certs"
cert="$cert_dir/registry.crt"
key="$cert_dir/registry.key"

# trust_cert adds $1 to the system trust store: Debian/Ubuntu (incl. WSL)
# via update-ca-certificates, or Fedora/RHEL via update-ca-trust — the only
# two this script covers. Both run sudo, so you see (and need to approve)
# a password prompt rather than this script silently escalating.
trust_cert() {
  local cert_path="$1"

  if command -v update-ca-certificates >/dev/null 2>&1; then
    echo "trusting $cert_path via update-ca-certificates (Debian/Ubuntu)..."
    sudo cp "$cert_path" /usr/local/share/ca-certificates/bomify-test-registry.crt
    sudo update-ca-certificates
  elif command -v update-ca-trust >/dev/null 2>&1; then
    echo "trusting $cert_path via update-ca-trust (Fedora/RHEL)..."
    sudo cp "$cert_path" /etc/pki/ca-trust/source/anchors/bomify-test-registry.crt
    sudo update-ca-trust extract
  else
    echo "no supported trust-store tool found (need update-ca-certificates or update-ca-trust) — trust $cert_path manually" >&2
    return 1
  fi

  echo "trusted $cert_path system-wide."
}

if [[ -f "$cert" && -f "$key" && "$force" == false ]]; then
  echo "certs already exist at $cert_dir (pass --force to regenerate)"
  exit 0
fi

mkdir -p "$cert_dir"

# MSYS_NO_PATHCONV: on Git Bash for Windows, MSYS rewrites an argument that
# looks like an absolute Unix path (e.g. "/CN=...") into a Windows path
# before openssl ever sees it. This disables that rewriting; it's a no-op
# on real Linux/macOS bash.
MSYS_NO_PATHCONV=1 \
openssl req -x509 -newkey rsa:2048 -nodes \
  -days 3650 \
  -keyout "$key" \
  -out "$cert" \
  -subj "/CN=bomify-test-registry" \
  -addext "subjectAltName=DNS:localhost,DNS:registry,DNS:bomify-test-registry,IP:127.0.0.1,IP:::1"

chmod 600 "$key"

echo "generated self-signed cert: $cert"
echo "generated private key:      $key"
echo

trust_cert "$cert" || true
