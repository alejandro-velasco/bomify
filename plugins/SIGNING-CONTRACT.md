# Signing plugin contract

The spec for a `bomify-plugin-<kind>` binary's **signing** subcommands,
`signature sign`, `signature attest`, `signature verify`, `signature
verify-attestation`, and `signature supported-types`, which `bomify
push`/`save --sign` and `bomify pull`/`load --verify` (or a matching
`bomify trust` rule) call. It's independent of the
[component](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md),
[SBOM generation](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md),
and [security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SECURITY-CONTRACT.md)
contracts.

Here `<kind>` names a signing scheme (e.g. `sigstore`, `notation`).

Go plugins should implement `pkg/plugin`'s `SigningPlugin` interface and
use `plugin.SignatureCommand`, which provides all five subcommands,
their flags, reading `--payload`/`--statement`/`--envelope`, and output.

## Naming and discovery

As for the [component contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md#naming-and-discovery):
`bomify-plugin-<kind>` (`.exe` on Windows), installed in
`<data-dir>/plugins`.

## What bomify does

A plugin only turns a payload into an envelope, and decides whether an
envelope is a trusted signature over a payload. bomify does the rest:

1. **Pack** the package as an OCI manifest, which pins the SBOM and every
   layer by digest, so one signature covers the whole package.
2. **Sign** (push/save): write the [payload](#payload), call `signature
   sign`, and push the envelope as a [referrer](#where-signatures-live)
   of the manifest, before tagging, so a failed signing never leaves a
   tag on an unsigned package.
3. **Verify** (pull/load): before fetching anything else, list the
   manifest's referrers, keep those whose artifact type `signature
   supported-types` lists, and call `signature verify` on each until one
   passes. If none does, the pull fails and nothing is written.
4. **Verify provenance** (pull/load with `--verify-provenance` or a
   trust rule's `--require-provenance`): the same way, call `signature
   verify-attestation` on each attestation referrer until one passes and
   bomify accepts the statement it returns.

The plugin never talks to a registry or sees the package's contents, so
it works the same for registries and `bomify save` tarballs.

## Payload

`--payload` names a file holding the package manifest's descriptor as
compact JSON, exactly these fields in this order:

```json
{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:ae88...","size":1234}
```

Treat it as opaque bytes: sign and verify exactly those bytes. bomify
produces it identically at sign and verify time. A plugin may parse it
(e.g. to embed the digest in a statement) but never needs to.

## Commands

```
bomify-plugin-<kind> signature sign            --payload <file> --reference <ref> [--option <key>=<value>]...
bomify-plugin-<kind> signature attest          --statement <file> --reference <ref> [--option <key>=<value>]...
bomify-plugin-<kind> signature verify          --payload <file> --envelope <file> --media-type <mt> --reference <ref> [--option <key>=<value>]...
bomify-plugin-<kind> signature verify-attestation --envelope <file> --media-type <mt> --subject <digest> --reference <ref> [--option <key>=<value>]...
bomify-plugin-<kind> signature supported-types
```

### `signature sign`

| Flag | Required | Meaning |
| --- | --- | --- |
| `--payload` | yes | The [payload](#payload) file to sign. |
| `--reference` | yes | The reference being published. Informational; use it to pick an identity, or ignore it. |
| `--option` | no, repeatable | A `key=value` from `--sign-option`. See [Options](#options). |

On success, print one [`SignResult`](#signresult) and exit `0`.

### `signature attest`

Called with `--sign` when the package has
[provenance](https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/provenance.md).

| Flag | Required | Meaning |
| --- | --- | --- |
| `--statement` | yes | An in-toto statement to attest, such as the package's build provenance. |
| `--reference` | yes | As for `sign`. |
| `--option` | no, repeatable | As for `sign`. |

Sign the statement as a [DSSE](https://github.com/secure-systems-lab/dsse)
envelope with payload type `application/vnd.in-toto+json`, in your
ecosystem's usual form, so its own tools can verify it (e.g. a Sigstore
bundle holding a DSSE envelope, which cosign and `gh attestation verify`
read). On success, print one [`SignResult`](#signresult), with any
annotations those tools use to find it (e.g. Sigstore's
`dev.sigstore.bundle.content` and `dev.sigstore.bundle.predicateType`),
and exit `0`. A plugin that can't produce DSSE must fail.

bomify stores an attestation as a referrer of the package like a
signature, annotated `land.bomify.attestation.predicateType`, and never
passes it to `signature verify` as a package signature, only to
[`signature verify-attestation`](#signature-verify-attestation).

### `signature verify`

| Flag | Required | Meaning |
| --- | --- | --- |
| `--payload` | yes | The [payload](#payload) the envelope must sign. |
| `--envelope` | yes | One envelope, byte for byte as some `sign` produced it (not necessarily this plugin's, nor a trusted signer's). |
| `--media-type` | yes | The envelope's media type, as its `sign` reported it. |
| `--reference` | yes | The reference being restored. Use it to scope trust, or ignore it. |
| `--option` | no, repeatable | A `key=value` from `--verify-option` or the matching trust rule. See [Options](#options). |

Print one [`VerifyResult`](#verifyresult) and exit `0` **only** if the
envelope is a valid signature over the payload by a signer the plugin
trusts. Anything else (bad signature, untrusted or unconfigured signer,
malformed envelope, unsupported media type) exits non-zero with one
stderr message. Fail closed: if trust can't be established, it's not
trusted.

### `signature verify-attestation`

| Flag | Required | Meaning |
| --- | --- | --- |
| `--envelope` | yes | One attestation envelope, byte for byte as some `attest` produced it (not necessarily this plugin's, nor a trusted signer's). |
| `--media-type` | yes | The envelope's media type, as its `attest` reported it. |
| `--subject` | yes | The package manifest's digest, `<algorithm>:<hex>` (e.g. `sha256:ae88...`). |
| `--reference` | yes | As for `verify`. |
| `--option` | no, repeatable | As for `verify`. |

Print one [`VerifyAttestationResult`](#verifyattestationresult) and exit
`0` **only** if the envelope is a DSSE envelope of payload type
`application/vnd.in-toto+json`, validly signed by a signer the plugin
trusts, whose statement names `--subject` among its subjects. Fail
otherwise, closed, as for `verify`. bomify checks the rest of the
statement itself.

### `signature supported-types`

No flags. Print one
[`SupportedSignatureTypesResult`](#supportedsignaturetypesresult) and
exit `0`. It must always report the same thing.

## Options

`--option key=value` carries everything scheme-specific: a key path, a
KMS URI, a certificate identity. bomify only checks that both sides are
non-empty and never interprets them. Reject unknown keys rather than
ignoring them, since a silently ignored verification option can weaken
what's checked.

A trust rule's stored key (`bomify trust create --key-option
key=<name>`) arrives as an ordinary `--option key=<path of bomify's
stored copy>`, so a plugin always gets a file path.

The plugin owns its trust material. bomify only decides whether a
package is signed or verified, and by which plugin: `--sign`/`--verify`,
else (for verification) the most specific trust rule (see
[the architecture docs](https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/signing.md)).

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one JSON result, only on success. Nothing else, ever. |
| stderr | One short fatal message, only on failure. bomify appends it to its error (per rejected envelope, for `verify`). There's no `--log` file. |
| exit code | `0` on success; non-zero on failure, including a valid signature by an untrusted signer. |

## SignResult

```json
{
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "envelope": "eyJtZWRpYVR5cGUiOi...",
  "annotations": {}
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `artifactType` | string | yes | Artifact type of the referrer that carries the envelope. Use your ecosystem's standard type (e.g. `application/vnd.cncf.notary.signature`) so its tooling can find it. Must be in your `supported-types`. |
| `mediaType` | string | yes | Media type of the envelope blob, passed back to `verify` as `--media-type`. |
| `envelope` | string (base64) | yes, non-empty | The envelope, standard base64. bomify stores the decoded bytes and passes exactly those to `verify`. |
| `annotations` | object | no | Extra annotations for the referrer. bomify adds `land.bomify.signature.plugin` (`<kind>`). |

Schema: [`sign-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/sign-result.schema.json).

## VerifyResult

```json
{ "signer": "key sha256:<base64 fingerprint of the public key>" }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `signer` | string | yes | Human-readable identity of the signer (key fingerprint, certificate subject, email). Logged only. |

Schema: [`verify-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/verify-result.schema.json).

## VerifyAttestationResult

```json
{ "signer": "key sha256:<base64 fingerprint of the public key>", "statement": "eyJfdHlwZSI6..." }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `signer` | string | yes | As for [`VerifyResult`](#verifyresult). |
| `statement` | string (base64) | yes, non-empty | The in-toto statement the envelope signs, exactly as signed, standard base64. |

Schema: [`verify-attestation-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/verify-attestation-result.schema.json).

## SupportedSignatureTypesResult

```json
{ "artifactTypes": ["application/vnd.dev.sigstore.bundle.v0.3+json"] }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `artifactTypes` | array of strings | yes, non-empty | Referrer artifact types `verify` and `verify-attestation` understand. bomify never passes them an envelope of another type. |

Schema: [`supported-signature-types-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/supported-signature-types-result.schema.json).

## Where signatures live

Each signature is an OCI 1.1 referrer of the package manifest: a
manifest of the plugin's `artifactType`, `subject` set to the package,
with the envelope as its one layer. Registries expose it through the
Referrers API (or its tag-schema fallback); a `save` tarball holds it as
an untagged manifest in `index.json`. Re-signing adds a signature rather
than replacing one, and verification needs only one to pass.
Signatures never go in the SBOM, whose hash is the package's identity.

## What bomify handles

Registry access, storage, choosing among a package's signatures, and
the policy on which packages need verifying are all bomify's. `sign`
should depend only on its flags and the plugin's keys; `verify` only on
its flags and trust configuration. Don't depend on the binary's other
contracts, if it has any.
