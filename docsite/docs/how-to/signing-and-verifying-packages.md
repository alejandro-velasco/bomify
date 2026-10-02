---
icon: lucide/badge-check
---

# Signing and verifying packages

A package is signed as a whole when pushed or saved, and verified before
it's pulled or loaded. One signature covers the SBOM and every component,
stored beside the package as an OCI referrer. Vulnerability reports and VEX
documents attached with `--vex` are signed and verified separately; one
that fails verification is skipped with a warning.

`bomify-plugin-sigstore` is the first-party signing plugin (`bomify
plugin install sigstore`). See
[the architecture docs](../development/architecture/signing.md)
for how it works and
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#bomify-plugin-sigstore)
for its options.

## 1. Create a key pair

Any PEM key pair works (ECDSA P-256 shown; RSA and Ed25519 work too):

=== "OpenSSL (password-protected)"

    ```sh
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -aes256 -out signing.key
    openssl pkey -in signing.key -pubout -out signing.pub
    ```

=== "OpenSSL (no password)"

    ```sh
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out signing.key
    openssl pkey -in signing.key -pubout -out signing.pub
    ```

=== "cosign"

    ```sh
    cosign generate-key-pair --output-key-prefix signing
    ```

Keep `signing.key` private; give `signing.pub` to whoever verifies.

## 2. Sign while pushing

For an encrypted key, set its password without echoing it:

```sh
printf 'Key password: '; read -rs SIGSTORE_PASSWORD; echo; export SIGSTORE_PASSWORD
bomify push registry.example.com/team/myapp:1.0 --sign sigstore --sign-option key=signing.key
unset SIGSTORE_PASSWORD
```

The signature is attached before the tag moves, so the tag never points
at an unsigned package. Signing again with another key adds a signature.

## 3. Verify while pulling

```sh
bomify pull registry.example.com/team/myapp:1.0 --verify sigstore --verify-option key=signing.pub
```

The signature is checked before anything is downloaded; if none
verifies, nothing is written.

## 4. Require verification with a trust rule

```sh
bomify trust create sigstore --match registry.example.com/team --option key=signing.pub
```

Now every `pull` and `load` under that prefix requires a signature that
key verifies. The most specific `--match` wins; `--verify` overrides the
rules and `--insecure-skip-verify` bypasses them with a warning. Add
`--require-provenance` to require build provenance too (see
[step 7](#7-attach-and-require-build-provenance)).

To stop the rule depending on where the key file lives, store the key
under a name. Re-adding the name rotates it for every rule using it.
Only public keys and certificates are accepted.

```sh
bomify trust key add team signing.pub
bomify trust create sigstore --match registry.example.com/team --key-option key=team
bomify trust key add team signing-2027.pub   # rotate
```

## 5. Offline tarballs

`save` and `load` take the same flags, and the signature travels inside
the tarball, so verification needs no network:

```sh
bomify save myapp:1.0 --output myapp.tar --sign sigstore --sign-option key=signing.key
bomify load --input myapp.tar --verify sigstore --verify-option key=signing.pub
```

## 6. Keyless signing in CI

With no `key`, the plugin exchanges an OIDC token from `SIGSTORE_ID_TOKEN`
for a short-lived certificate naming the workflow, and logs the
signature publicly. There are no secrets to manage; bomify's own plugins
are signed this way. In GitHub Actions, fetch the token right before
pushing, since it lasts minutes:

```yaml
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      packages: write
    steps:
      # ... install bomify and bomify-plugin-sigstore, log in ...
      - id: oidc
        uses: actions/github-script@v7
        with:
          script: core.setOutput('token', await core.getIDToken('sigstore'))
      - run: bomify push ghcr.io/my-org/myapp:1.0 --sign sigstore
        env:
          SIGSTORE_ID_TOKEN: ${{ steps.oidc.outputs.token }}
```

Verify by naming the workflow and issuer instead of a key (this needs
network access to Sigstore). The same options work in a trust rule.

```sh
bomify pull ghcr.io/my-org/myapp:1.0 --verify sigstore \
  --verify-option certificate-identity=https://github.com/my-org/myapp/.github/workflows/publish.yml@refs/heads/main \
  --verify-option certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

## 7. Attach and require build provenance

Record SLSA provenance when you build, and it's attached to the package
as an in-toto attestation on push or save, signed with `--sign`:

```sh
bomify build sbom.json --tag ghcr.io/my-org/myapp:1.0 --provenance
bomify push ghcr.io/my-org/myapp:1.0 --sign sigstore
```

With `bomify-plugin-sigstore`, it's a Sigstore bundle attestation
stored as an OCI referrer, the format cosign's bundle support and `gh
attestation verify` read.

To require it when pulling or loading, add `--verify-provenance`. The
provenance must be signed by a signer the same plugin and options trust,
be about this very package and SBOM, and come from a bomify build:

```sh
bomify pull ghcr.io/my-org/myapp:1.0 --verify sigstore   --verify-option certificate-identity=https://github.com/my-org/myapp/.github/workflows/publish.yml@refs/heads/main   --verify-option certificate-oidc-issuer=https://token.actions.githubusercontent.com   --verify-provenance
```

See [Build provenance](../development/architecture/provenance.md#verifying).
