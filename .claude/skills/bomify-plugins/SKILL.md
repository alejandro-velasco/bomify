---
name: bomify-plugins
description: Use when writing, reviewing, or modifying a bomify-plugin-<kind> binary — its subcommands, flags, JSON result shapes, hashing, or logging, for the component plugin contract (component pull/push/remote), the SBOM generation contract (sbom generate), the security scanning contract (security scan/security supported-components), or the signing contract (signature sign/verify/supported-types). Points to the authoritative spec rather than restating it.
---

# bomify plugins

A `bomify-plugin-<kind>` binary can implement any of four independent
contracts. Work out which one your task concerns, then read that
contract **in full**; it's authoritative. Don't restate it in code
comments or rely on memory of it, since the contracts keep growing.

| Contract | Subcommands | Spec |
| --- | --- | --- |
| Component | `component pull/push/remote` | [`COMPONENT-CONTRACT.md`](../../../plugins/COMPONENT-CONTRACT.md) |
| SBOM generation | `sbom generate` | [`SBOM-CONTRACT.md`](../../../plugins/SBOM-CONTRACT.md) |
| Security scanning | `security scan/supported-components` | [`SECURITY-CONTRACT.md`](../../../plugins/SECURITY-CONTRACT.md) |
| Signing | `signature sign/verify/supported-types` | [`SIGNING-CONTRACT.md`](../../../plugins/SIGNING-CONTRACT.md) |

Also relevant:

- [`pkg/plugin`](../../../pkg/plugin): the Go library for plugins. It has
  one type per JSON result plus `Print`, and one interface and command
  builder per contract (`ComponentCommand`, `SecurityCommand`,
  `SignatureCommand`, plus `NewRootCommand`/`Run`) that implement the
  flags, validation, logging, and output. Contract changes to flags or
  output belong in these builders, not in each plugin. Check the package
  for its current API. SBOM generation has no equivalent, by design.
- `plugins/*.schema.json`: one JSON Schema per result shape bomify
  parses (SBOM generation has none). Glob for the current set.
- [`plugins/README.md`](../../../plugins/README.md): the first-party
  plugins.
- [`ARCHITECTURE.md`](../../../ARCHITECTURE.md): how the contracts fit
  into bomify.

## Workflow

1. Read the whole contract, every subcommand: a mode like `--check` can
   change another subcommand's requirements.
2. Implement it exactly: every subcommand, flag, mode, and result shape.
3. For a breaking change or new requirement, update the contract and any
   affected schema (adding one for a new result shape) in the same
   change, and check every first-party plugin still conforms. Never let
   a change to one contract imply another.
4. For a new first-party plugin, or a change to a plugin's main
   features, update `plugins/README.md`.
