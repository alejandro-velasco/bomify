---
icon: lucide/badge-check
---

# Signing and verifying packages

A package can be signed as a whole when it's pushed or saved, and
verified before it's pulled or loaded. One signature covers everything
in the package — the SBOM, every component, and every vulnerability
report — and is stored next to it as an OCI referrer, never inside the
SBOM. Signing is done by a signing plugin; `bomify-plugin-sigstore` is
bomify's first-party one, producing standard Sigstore bundles. See
[ARCHITECTURE.md](https://github.com/alejandro-velasco/bomify/blob/main/ARCHITECTURE.md#signing--verification)
for how it works, and
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#bomify-plugin-sigstore)
for the plugin's own options.

Requires [`bomify-plugin-sigstore`](../getting-started/installing-plugins.md)
to be on `PATH`.

## 1. Create a key pair

Key-based signing needs a private key to sign with and its public key
to verify with, both as PEM files. Any of these works — pick whichever
tool you already have.

=== "OpenSSL (password-protected)"

    ```sh
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -aes256 -out signing.key
    openssl pkey -in signing.key -pubout -out signing.pub
    ```

    OpenSSL prompts for the password. Export it as `SIGSTORE_PASSWORD`
    whenever you sign.

=== "OpenSSL (no password)"

    ```sh
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out signing.key
    openssl pkey -in signing.key -pubout -out signing.pub
    ```

    No `SIGSTORE_PASSWORD` needed — but anyone who can read
    `signing.key` can sign as you, so keep it somewhere safe.

=== "cosign"

    ```sh
    cosign generate-key-pair --output-key-prefix signing
    ```

    Writes `signing.key` (encrypted) and `signing.pub`. cosign prompts
    for the password; export it as `SIGSTORE_PASSWORD` whenever you
    sign.

ECDSA P-256 is shown above, but RSA and Ed25519 keys work too. Keep
`signing.key` private; hand `signing.pub` to whoever will verify.

## 2. Sign while pushing

```sh
export SIGSTORE_PASSWORD='your-key-password'   # omit for an unencrypted key
bomify push registry.example.com/team/myapp:1.0 \
  --sign sigstore --sign-option key=signing.key
```

The signature is attached before the tag is updated, so the tag never
points at an unsigned package. Pushing again with another key adds a
second signature rather than replacing the first.

## 3. Verify while pulling

```sh
bomify pull registry.example.com/team/myapp:1.0 \
  --verify sigstore --verify-option key=signing.pub
```

The signature is checked before anything is downloaded. If no signature
verifies, the pull fails and nothing is written to the data directory.

## 4. Require verification with a trust rule

Instead of remembering `--verify` on every pull, record which packages
must be signed, and by whom:

```sh
bomify trust create sigstore --match registry.example.com/team --option key=signing.pub
```

Every `bomify pull` or `bomify load` of a package under
`registry.example.com/team` now fails unless it carries a signature
that key verifies. The most specific `--match` wins when several rules
apply; `bomify trust list` shows them all. An explicit `--verify`
overrides the rules, and `--insecure-skip-verify` bypasses them (with a
warning). See [bomify trust create](../usage/reference/bomify_trust_create.md)
for the full reference.

## 5. Sign and verify offline tarballs

`save` and `load` take the same flags. The signature travels inside
the tarball, so the signature can be checked on a machine with no
network access at all:

```sh
bomify save myapp:1.0 --output myapp.tar --sign sigstore --sign-option key=signing.key
bomify load --input myapp.tar --verify sigstore --verify-option key=signing.pub
```
