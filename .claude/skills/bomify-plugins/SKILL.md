---
name: bomify-plugins
description: Use when writing, reviewing, or modifying a bomify-plugin-<kind> binary — its subcommands, flags, JSON result shapes, hashing, or logging, for the component plugin contract (component pull/push/remote), the SBOM generation contract (sbom generate), the security scanning contract (security scan/security supported-components), or the signing contract (signature sign/attest/verify/verify-attestation/supported-types). Points to the authoritative spec rather than restating it.
---

# bomify plugins

A `bomify-plugin-<kind>` binary can implement any of four independent
contracts. Work out which one your task concerns, then read that
contract **in full**; it's authoritative. Don't restate it in code
comments or rely on memory of it, since the contracts keep growing.

| Contract | Subcommands | Spec |
| --- | --- | --- |
| Component | `component pull/push/remote` | [`contracts/component/v1`](../../../plugins/contracts/component/v1/CONTRACT.md) |
| SBOM generation | `sbom generate` | [`contracts/sbom/v1`](../../../plugins/contracts/sbom/v1/CONTRACT.md) |
| Security scanning | `security scan/supported-components` | [`contracts/security/v1`](../../../plugins/contracts/security/v1/CONTRACT.md) |
| Signing | `signature sign/attest/verify/verify-attestation/supported-types` | [`contracts/signing/v1`](../../../plugins/contracts/signing/v1/CONTRACT.md) |

Also relevant:

- [`pkg/plugin`](../../../pkg/plugin): the Go library for plugins. It has
  one type per JSON result plus `Print`, and one interface and command
  builder per contract (`ComponentCommand`, `SecurityCommand`,
  `SignatureCommand`, `SBOMCommand`, plus `NewRootCommand`/`Run`) that implement the
  flags, validation, logging, and output. Contract changes to flags or
  output belong in these builders, not in each plugin. Check the package
  for its current API.
- `plugins/contracts/<contract>/v<N>/*.schema.json`: one JSON Schema per
  result shape bomify parses, next to that version's spec. Glob for the
  current set.
  `plugins/contracts/contract-result.schema.json` is the `contract`
  command's, shared by all. A CycloneDX object in a result (a
  component, a vulnerability, a whole SBOM) `$ref`s CycloneDX's own
  schema rather than restating it, adding only bomify's constraints
  beside it in an `allOf`. In Go, the same objects are cyclonedx-go's
  types, decoded with `DisallowUnknownFields`.
- [`plugins/README.md`](../../../plugins/README.md): the first-party
  plugins.
- [`docs/architecture/plugins.md`](../../../docs/architecture/plugins.md):
  how the contracts fit into bomify.

## Third-party APIs

A first-party plugin that calls an external service directly must match
that service's own spec. Check every request and response against it,
not memory, when writing or changing the plugin:

| Plugin | Spec | Covers |
| --- | --- | --- |
| `bomify-plugin-huggingface` | Hugging Face Hub [OpenAPI spec](https://huggingface.co/.well-known/openapi.md) | Bearer auth; pull: the tree listing (`/api/models/{namespace}/{repo}/tree/{rev}`, `recursive`, `limit`/`cursor` paging) and file downloads (`/{namespace}/{repo}/resolve/{rev}/{path}`, its redirects); push: `preupload`, the NDJSON `commit`, and `whoami-v2`; `sbom generate`: model info (`/api/models/{namespace}/{repo}/revision/{rev}`). |
| `bomify-plugin-huggingface` | [Git LFS batch API](https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md) | Push's LFS uploads (`{repo}.git/info/lfs/objects/batch`, `basic` and `multipart` transfers), which the Hub's spec leaves out, as it does repo creation (`/api/repos/create`). For those, and the Hub's multipart variant, [`huggingface_hub`](https://github.com/huggingface/huggingface_hub)'s `lfs.py`, `_commit_api.py`, and `HfApi.create_repo` are the reference. |

Where a spec leaves behavior out (the Hub's spec doesn't document its
`Link` paging header, its `X-Error-*` headers, or some response fields,
for example), confirm it against the live service or the reference
client, and test it with a fake server in the plugin's tests.

## Workflow

1. Read the whole contract, every subcommand: a mode like `--check` can
   change another subcommand's requirements.
2. Implement it exactly: every subcommand, flag, mode, and result shape.
3. For a breaking change or new requirement, update the contract and any
   affected schema (adding one for a new result shape, and listing it
   under "Schemas" on the contract's docsite page) in the same change,
   and check every first-party plugin still conforms. Never let a
   change to one contract imply another.
4. If that change breaks a plugin or bomify written for the current
   version, make it in a new version instead, in the same change: copy
   `plugins/contracts/<contract>/v<N>/` to `v<N+1>/` and edit the copy,
   leaving `v<N>/` as it was. Then point everything current at it: the
   title, every schema's `$id`, the docsite wrapper and its
   `docsite/zensical.toml` nav entry, the links to the spec, `pkg/plugin`'s
   `<Contract>ContractVersion`, and the tests that expect it (see
   [contract versions](../../../plugins/README.md#contract-versions)).
5. For a new first-party plugin, or a change to a plugin's main
   features, update `plugins/README.md`.
