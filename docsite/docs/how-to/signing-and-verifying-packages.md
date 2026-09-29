---
icon: lucide/badge-check
---

# Signing and verifying packages

A package can be signed as a whole when it's pushed or saved, and
verified before it's pulled or loaded. One signature covers everything
in the package — the SBOM and every component — and is stored next to
it as an OCI referrer, never inside the SBOM. The package's
vulnerability reports live in a referrer of their own, which is signed
and verified the same way; a report that fails verification is skipped
with a warning rather than failing the pull. Signing is done by a signing plugin; `bomify-plugin-sigstore` is
bomify's first-party one, producing standard Sigstore bundles. See
[ARCHITECTURE.md](https://github.com/alejandro-velasco/bomify/blob/main/ARCHITECTURE.md#signing--verification)
for how it works, and
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#bomify-plugin-sigstore)
for the plugin's own options.

Requires [`bomify-plugin-sigstore`](../getting-started/installing-plugins.md)
to be installed (`bomify plugin install sigstore`).

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

    OpenSSL prompts for the password; you'll provide it as
    `SIGSTORE_PASSWORD` when signing (see step 2).

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
    for the password; you'll provide it as `SIGSTORE_PASSWORD` when
    signing (see step 2).

ECDSA P-256 is shown above, but RSA and Ed25519 keys work too. Keep
`signing.key` private; hand `signing.pub` to whoever will verify.

## 2. Sign while pushing

For an encrypted key, read its password into `SIGSTORE_PASSWORD` without
echoing it or leaving it in your shell history (skip this for an
unencrypted key):

```sh
printf 'Key password: '; read -rs SIGSTORE_PASSWORD; echo
export SIGSTORE_PASSWORD
```

Then push and sign:

```sh
bomify push registry.example.com/team/myapp:1.0 \
  --sign sigstore --sign-option key=signing.key
```

Run `unset SIGSTORE_PASSWORD` once you're done signing.

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

## 6. Sign keyless from GitHub Actions

Instead of managing a key pair at all, a GitHub Actions workflow can
sign as itself: with no `key` option, `bomify-plugin-sigstore` takes
the OIDC identity token in `SIGSTORE_ID_TOKEN`, exchanges it with
Sigstore for a short-lived certificate naming the workflow, and records
the signature in Sigstore's public transparency log. Nothing secret is
stored anywhere. bomify's own plugins are published exactly this way.

Grant the job permission to request a token, fetch one for the
`sigstore` audience right before pushing (it only lasts minutes), and
push with `--sign sigstore` and no options:

```yaml
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # lets the job request its own identity token
      packages: write
    steps:
      # ... install bomify and bomify-plugin-sigstore, log in to the registry ...
      - id: oidc
        uses: actions/github-script@v7
        with:
          script: core.setOutput('token', await core.getIDToken('sigstore'))
      - run: bomify push ghcr.io/my-org/myapp:1.0 --sign sigstore
        env:
          SIGSTORE_ID_TOKEN: ${{ steps.oidc.outputs.token }}
```

Any other CI system with an OIDC provider works the same way: put its
token in `SIGSTORE_ID_TOKEN`.

Verify by naming the workflow that must have signed it — its file and
the ref it ran on — and GitHub's token issuer, instead of a key:

```sh
bomify pull ghcr.io/my-org/myapp:1.0 --verify sigstore \
  --verify-option certificate-identity=https://github.com/my-org/myapp/.github/workflows/publish.yml@refs/heads/main \
  --verify-option certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

The same options work in a trust rule. Keyless verification checks the
signature against Sigstore's public infrastructure, so unlike a key
pair it needs network access.
