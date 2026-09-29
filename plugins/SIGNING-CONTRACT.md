# Signing plugin contract

This is the specification for the subprocess contract between `bomify`
and a `bomify-plugin-<kind>` binary's **signing** subcommands, `signature
sign`, `signature verify`, and `signature supported-types`, which
`bomify push --sign`/`bomify save --sign` and `bomify pull --verify`/
`bomify load --verify` (or a matching `bomify trust` rule) delegate to.
It's an entirely independent contract from the
[component plugin contract](COMPONENT-CONTRACT.md), the
[SBOM generation plugin contract](SBOM-CONTRACT.md), and the
[security scanning plugin contract](SECURITY-CONTRACT.md) — a plugin
binary may implement any, all, or none of the four, and implementing one
owes nothing to the others.

`<kind>` here names a **signing scheme or tool** (e.g. `sigstore`,
`notation`), not a purl type, deployment medium, or scanning tool.

## Naming and discovery

Identical to the [component contract's](COMPONENT-CONTRACT.md#naming-and-discovery):
a plugin for signing scheme `<kind>` must be named exactly
`bomify-plugin-<kind>` (`bomify-plugin-<kind>.exe` on Windows) and
installed in `<data-dir>/plugins`.

## What bomify does

A plugin only ever turns a payload into a signature envelope, and
decides whether an envelope is a trusted signature over a payload.
Everything else is bomify's:

1. **Pack** the package as an OCI manifest, exactly as it would
   unsigned. That manifest pins the SBOM config, every component layer,
   and every vulnerability report by digest, so one signature over it
   covers the whole package.
2. **Sign** (push/save): write the [payload](#payload) for that manifest
   to a file, call `signature sign`, and push the returned envelope as
   an [OCI referrer](#where-signatures-live) of the manifest — before
   the tag is updated, so a failed signing never leaves a tag pointing
   at an unsigned package.
3. **Verify** (pull/load): after resolving the reference but **before
   fetching or writing anything else**, list the manifest's referrers,
   keep only those whose artifact type `signature supported-types`
   reports, write the payload and each candidate envelope to files, and
   call `signature verify` on each in turn. The first one that succeeds
   lets the pull proceed; if there are none, or every one fails, the
   pull fails and nothing is written to the data directory.

A plugin never talks to a registry, never sees the package's contents,
and never learns where its envelope is stored. The same plugin
therefore works identically for a registry (`push`/`pull`) and for a
`bomify save` tarball (`save`/`load`), which carries its referrers
along inside it.

## Payload

The file named by `--payload` holds a compact JSON object describing the
package's OCI manifest — exactly these three fields, in this order, and
nothing else:

```json
{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:ae88...","size":1234}
```

A plugin must treat it as opaque bytes: sign exactly those bytes, and
verify a signature against exactly those bytes. bomify computes it
identically at sign and verify time, so a plugin never needs to parse
or canonicalize it (though it may, e.g. to embed the digest in a
format-specific statement).

## Commands

```
bomify-plugin-<kind> signature sign            --payload <file> --reference <ref> [--option <key>=<value>]...
bomify-plugin-<kind> signature verify          --payload <file> --envelope <file> --media-type <mt> --reference <ref> [--option <key>=<value>]...
bomify-plugin-<kind> signature supported-types
```

### `signature sign`

| Flag | Required | Meaning |
| --- | --- | --- |
| `--payload` | yes | *Path to the [payload](#payload) file to sign.* |
| `--reference` | yes | *The reference the package is being published as — the `bomify push` tag, or a `bomify save` tag. Informational; a plugin may use it to pick an identity, or ignore it.* |
| `--option` | no, repeatable | *One `key=value` option, passed through from `--sign-option` unparsed. See [Options](#options).* |

On success, print a single [`SignResult`](#signresult) object to stdout
and exit `0`.

### `signature verify`

| Flag | Required | Meaning |
| --- | --- | --- |
| `--payload` | yes | *Path to the [payload](#payload) file the envelope must sign.* |
| `--envelope` | yes | *Path to a file holding one envelope, byte-for-byte as some `signature sign` reported it (not necessarily this plugin's, nor a trusted signer's).* |
| `--media-type` | yes | *The envelope's media type, as its `sign` reported it.* |
| `--reference` | yes | *The reference the package is being restored from. A plugin may use it to scope which identities it trusts, or ignore it.* |
| `--option` | no, repeatable | *One `key=value` option, from `--verify-option` or the matching `bomify trust` rule. See [Options](#options).* |

Exit `0` and print a single [`VerifyResult`](#verifyresult) object to
stdout **only** if the envelope is a valid signature over the payload
by a signer the plugin's trust configuration accepts. Anything else —
a bad signature, an untrusted or unconfigured signer, a malformed
envelope, an unsupported media type — is a failure: exit non-zero with
one message on stderr. A plugin must fail closed: if it can't tell
whether a signature is trusted, it isn't.

### `signature supported-types`

Takes no flags. On success, print a single
[`SupportedSignatureTypesResult`](#supportedsignaturetypesresult)
object to stdout and exit `0`. It must be a pure function of nothing at
all.

## Options

`--option key=value` carries everything scheme-specific — a key path, a
KMS URI, a certificate identity, a trust store name. bomify validates
only that each is `key=value` with neither side empty, and never
interprets one — so a plugin never receives an empty value. A plugin should
reject a key it doesn't recognize rather than ignore it, since a
mistyped verification option silently ignored could weaken what gets
checked.

A plugin owns its own trust material. bomify only decides *whether* a
package must be signed or verified, and *which plugin* does it: an
explicit `--sign`/`--verify` flag, else (for verification) the
most specific `bomify trust` rule matching the reference (see
[ARCHITECTURE.md](https://github.com/alejandro-velasco/bomify/blob/main/ARCHITECTURE.md#signing--verification)).

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one JSON value, printed only on success — a `SignResult`, `VerifyResult`, or `SupportedSignatureTypesResult`, depending on the subcommand. Nothing else, ever. |
| stderr | A single, short, human-readable fatal error message, written only on failure. bomify appends it verbatim to the error it reports; for `verify`, it's listed per rejected envelope. As with the security scanning contract, there's no `--log` file. |
| exit code | `0` on success (with valid JSON on stdout). Any non-zero value on failure — for `verify`, that includes "valid signature, untrusted signer". |

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
| `artifactType` | string | yes | The artifact type of the referrer manifest bomify pushes to carry the envelope. Use your signing ecosystem's own standard type (e.g. `application/vnd.dev.sigstore.bundle.v0.3+json`, `application/vnd.cncf.notary.signature`) rather than a bomify-specific one, so that ecosystem's tooling can discover it too. It must also appear in your `supported-types`. |
| `mediaType` | string | yes | The media type of the envelope blob itself, passed back to `verify` as `--media-type`. |
| `envelope` | string (base64) | yes, non-empty | The signature envelope, standard base64-encoded. bomify stores the decoded bytes verbatim and hands exactly those bytes back to `verify`. |
| `annotations` | object | no | Extra annotations for the referrer manifest. bomify adds its own `land.bomify.signature.plugin` (the plugin's `<kind>`) alongside them. |

A machine-readable version of this schema is published at
[`sign-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/sign-result.schema.json).

## VerifyResult

```json
{ "signer": "key sha256:<base64 fingerprint of the public key>" }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `signer` | string | yes | A human-readable identity of whoever made the signature — a key fingerprint, certificate subject, email address, etc. bomify only logs it. |

A machine-readable version of this schema is published at
[`verify-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/verify-result.schema.json).

## SupportedSignatureTypesResult

```json
{ "artifactTypes": ["application/vnd.dev.sigstore.bundle.v0.3+json"] }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `artifactTypes` | array of strings | yes, non-empty | The referrer artifact types this plugin's `verify` understands. bomify never passes `verify` an envelope from a referrer of any other type. |

A machine-readable version of this schema is published at
[`supported-signature-types-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/supported-signature-types-result.schema.json).

Go plugins should build all three results as `plugin.SignResult`,
`plugin.VerifyResult`, and `plugin.SupportedSignatureTypesResult` (see
[`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin))
and print them with their `Print` methods, rather than hand-rolling the
JSON encoding.

## Where signatures live

Each signature is an OCI 1.1 **referrer** of the package's manifest: a
manifest of the plugin's `artifactType`, whose `subject` is the package
manifest and whose single layer is the envelope blob. In a registry
it's discovered through the Referrers API (or its tag-schema fallback,
for registries without one); in a `bomify save` tarball it's an
untagged manifest in the OCI layout's `index.json`. A package can carry
any number of signatures — re-signing adds one rather than replacing
any — and verification needs only one to pass.

Signatures are never embedded in the SBOM itself: the SBOM's content
hash is the package's identity, so it stays byte-for-byte what `bomify
build` recorded.

## What a plugin does *not* need to handle

- No registry access, authentication, or storage — bomify pushes and
  fetches every envelope itself.
- No filtering or selection among a package's signatures — bomify
  hands `verify` one candidate envelope at a time, only of the types
  `supported-types` reports, and succeeds on the first that passes.
- No policy about *which* packages must be verified — that's
  `--verify` and `bomify trust`, on bomify's side.
- No coordination with this binary's component, SBOM generation, or
  security scanning subcommands (if it has any) — the four contracts
  must not depend on each other's behavior or state.

`signature sign` should depend only on its flags and the plugin's own
key material; `signature verify` should be a pure function of its
flags and trust configuration.
