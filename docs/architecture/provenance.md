# Build provenance

`bomify build --provenance` records how a package was built, as a
[SLSA v1 provenance](https://slsa.dev/provenance/v1) predicate. When the
package is pushed or saved, it's attached as an
[in-toto](https://in-toto.io) attestation about the package, for tools
such as `cosign verify-attestation`, `slsa-verifier`, and `gh attestation
verify` to check. bomify itself doesn't check provenance on pull.

This page is also the `buildType` of that provenance,
`https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/provenance.md`,
so it defines what the fields below mean.

## Recording

[`internal/provenance`](https://github.com/alejandro-velasco/bomify/tree/main/internal/provenance)'s
`Recorder` collects dependencies as `bomify build` pulls components
(concurrently), then writes the predicate to
`<data-dir>/provenance/<sbom-hash>.json` (`layout.Provenance`) once the
build is recorded. Building the same SBOM again with `--provenance`
replaces it, and pruning removes it with its build. `--provenance` can't
be combined with `--check`, which records nothing.

The predicate and statement use the in-toto project's Go types
([`in-toto/attestation`](https://github.com/in-toto/attestation)) and
are validated against the spec as they're written, so a malformed
digest (e.g. a plugin reporting a SHA-256 that isn't 64 hex digits)
fails the build. Only `externalParameters` is bomify's own schema.

| Field | Contents |
| --- | --- |
| `buildDefinition.buildType` | This page's URL. |
| `externalParameters.sbom` | The SBOM, by its SHA-256 (the build's identity). |
| `externalParameters.tags` | The `--tag`s given. |
| `resolvedDependencies` | Every component, by purl, with the SHA-256 its plugin reported (none if it reported none); and every plugin used, as `pkg:bomify-plugin/<kind>[@<version>]` with its binary's SHA-256. The version comes from `bomify plugin install`'s record, only if the installed binary still matches it. Sorted by URI. |
| `runDetails.builder.id` | `https://github.com/alejandro-velasco/bomify`, with `version.bomify` set to bomify's version. |
| `runDetails.metadata` | `startedOn` and `finishedOn`, and `invocationId` if `BOMIFY_INVOCATION_ID` is set: the CI run that built it, e.g. the job's URL. |

## Attaching

`push.Push` (and so `save`) calls `provenance.Attach` if the build has a
record. It builds an in-toto statement whose subject is the package
manifest digest, named by the reference's repository (e.g.
`registry.example.com/team/app`), and attaches it as a referrer of the
package, annotated `land.bomify.attestation.predicateType` and with the
statement's SHA-256 (`land.bomify.provenance.statement`). If the package
already carries a referrer with that statement, nothing is attached, so
pushing again adds nothing new.

- **With `--sign`**: `signature.NewAttester` has the signing plugin sign
  the statement as a DSSE envelope (`signature attest`, see the
  [signing contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SIGNING-CONTRACT.md#signature-attest)),
  pushed as a referrer of the plugin's artifact type. With
  `bomify-plugin-sigstore`, that's a Sigstore bundle carrying Sigstore's
  own annotations, in the form cosign and `gh` read.
- **Without `--sign`**: the statement is attached unsigned (artifact type
  and layer `application/vnd.in-toto+json`), readable but not verifiable
  by other tools.

Package signature verification (`signature.Verify`) skips referrers
annotated `land.bomify.attestation.predicateType`, so an attestation,
signed by the same plugin and so of the same artifact type, is never
taken for the package's own signature.

Provenance isn't restored by `pull` or `load`, so re-pushing a pulled
package doesn't carry it forward.

## SLSA levels

This meets Build L1 (provenance exists). Run in CI with keyless signing,
where the certificate names the workflow, it meets Build L2 (signed
provenance from a hosted build platform). L3 depends on hardening the
build platform itself, not on bomify.
