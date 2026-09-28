---
icon: lucide/badge-check
---

# Signing and verifying packages

A package can be signed as a whole when it's pushed or saved, and
verified before it's pulled or loaded. One signature covers everything
in the package — the SBOM, every component, and every vulnerability
report — and is stored next to it as an OCI referrer, never inside the
SBOM. Signing is done by a signing plugin; `bomify-plugin-cosign` is
bomify's first-party one, producing Sigstore bundles the same way
cosign does. See
[ARCHITECTURE.md](https://github.com/alejandro-velasco/bomify/blob/main/ARCHITECTURE.md#signing--verification)
for how it works, and
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#bomify-plugin-cosign)
for the plugin's own options.

Requires [`bomify-plugin-cosign`](../getting-started/installing-plugins.md)
to be on `PATH`.

## 1. Sign while pushing

With a key pair from `cosign generate-key-pair` (its password in
`COSIGN_PASSWORD`, as cosign expects):

```sh
bomify push registry.example.com/team/myapp:1.0 \
  --sign cosign --sign-option key=cosign.key
```

The signature is attached before the tag is updated, so the tag never
points at an unsigned package. Pushing again with another key adds a
second signature rather than replacing the first.

To sign keylessly instead — a short-lived certificate for your OIDC
identity, recorded in Sigstore's public transparency log — leave out
`key` and provide an identity token:

```sh
SIGSTORE_ID_TOKEN=... bomify push registry.example.com/team/myapp:1.0 --sign cosign
```

## 2. Verify while pulling

```sh
bomify pull registry.example.com/team/myapp:1.0 \
  --verify cosign --verify-option key=cosign.pub
```

For a keyless signature, name the identity you trust instead of a key:

```sh
bomify pull registry.example.com/team/myapp:1.0 --verify cosign \
  --verify-option certificate-identity=release@example.com \
  --verify-option certificate-oidc-issuer=https://accounts.google.com
```

The signature is checked before anything is downloaded. If no signature
verifies, the pull fails and nothing is written to the data directory.

## 3. Require verification with a trust rule

Instead of remembering `--verify` on every pull, record which packages
must be signed, and by whom:

```sh
bomify trust create cosign --match registry.example.com/team --option key=cosign.pub
```

Every `bomify pull` or `bomify load` of a package under
`registry.example.com/team` now fails unless it carries a signature
that key verifies. The most specific `--match` wins when several rules
apply; `bomify trust list` shows them all. An explicit `--verify`
overrides the rules, and `--insecure-skip-verify` bypasses them (with a
warning). See [bomify trust create](../usage/reference/bomify_trust_create.md)
for the full reference.

## 4. Sign and verify offline tarballs

`save` and `load` take the same flags. The signature travels inside
the tarball, so a key-based signature can be checked on a machine with
no network access at all:

```sh
bomify save myapp:1.0 --output myapp.tar --sign cosign --sign-option key=cosign.key
bomify load --input myapp.tar --verify cosign --verify-option key=cosign.pub
```
