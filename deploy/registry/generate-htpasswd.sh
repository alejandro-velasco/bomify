#!/usr/bin/env bash
set -euo pipefail

# Generates auth/htpasswd for the local test registry, so it requires
# authentication — letting `bomify login`/`push`/`pull` be exercised
# against a registry that actually checks credentials, not just an
# anonymous one.
#
# Idempotent: does nothing if auth/htpasswd already exists, unless
# --force is passed.

cd "$(dirname "${BASH_SOURCE[0]}")"

force=false
if [[ "${1:-}" == "--force" ]]; then
  force=true
fi

username="${REGISTRY_USER:-testuser}"
password="${REGISTRY_PASSWORD:-testpassword}"
port="${PORT:-443}"

auth_dir="auth"
htpasswd_file="$auth_dir/htpasswd"

if [[ -f "$htpasswd_file" && "$force" == false ]]; then
  echo "$htpasswd_file already exists (pass --force to regenerate)"
  exit 0
fi

mkdir -p "$auth_dir"

# -B: bcrypt (required — the registry's htpasswd auth handler only
# accepts bcrypt hashes). -b: read the password from argv instead of
# prompting. -c: create a new file (safe here since the existence check
# above already gates this).
htpasswd -Bbc "$htpasswd_file" "$username" "$password" >/dev/null

host="localhost"
if [[ "$port" != "443" ]]; then
  host="localhost:$port"
fi

echo "generated $htpasswd_file for user \"$username\""
echo "log in to this registry with: bomify login $host -u $username -p $password"
