---
name: bomify-plugins
description: Use when writing, reviewing, or modifying a bomify-plugin-<kind> binary — its subcommands, flags, JSON result shapes, hashing, or logging, for the component plugin contract (component pull/push/remote), the SBOM generation contract (sbom generate), or the security scanning contract (security scan/security supported-components). Points to the authoritative spec rather than restating it.
---

# bomify plugins

A `bomify-plugin-<kind>` is a standalone executable bomify shells out to.
It can implement any, all, or none of three entirely independent
contracts — determine which one your task concerns before reading further,
since they don't share requirements:

- **Component plugins** (`component pull`/`component push`/`component
  remote`, one per purl type) — the full subprocess contract, naming and
  discovery, every subcommand and its flags, stdout/stderr/exit-code
  rules, each JSON result shape, hash algorithm names, logging via
  `--log`, and what a plugin does *not* need to handle — is specified in
  [`plugins/COMPONENT-CONTRACT.md`](../../../plugins/COMPONENT-CONTRACT.md).
- **SBOM generation plugins** (`sbom generate`, one per deployment
  medium) — a deliberately much lighter contract, standalone-runnable
  and unrelated to the component contract's flags/JSON/logging/caching
  machinery — specified in
  [`plugins/SBOM-CONTRACT.md`](../../../plugins/SBOM-CONTRACT.md).
- **Security scanning plugins** (`security scan --purl <purl>` and
  `security supported-components`, one per scanning tool — e.g. `grype`,
  not a purl type or deployment medium) — closer in shape to the
  component contract than to SBOM generation: bomify itself loads the
  SBOM, queries `supported-components` once to decide which components
  are even worth scanning, dispatches one `scan` call per remaining
  component (concurrently, like `bomify build`/`bomify distribute`), and
  merges the JSON array each call returns — specified in
  [`plugins/SECURITY-CONTRACT.md`](../../../plugins/SECURITY-CONTRACT.md).

Treat whichever applies as authoritative; do not re-derive or paraphrase
any contract here or in code comments — read it directly, in full,
before implementing or changing plugin behavior. Don't assume a contract's
subcommands/flags/behavior stop at whatever an older skim or memory of it
suggested — re-read the contract file itself; each has grown before (the
component contract gained `remote` and `--check` after starting as just
`pull`/`push`) and will likely again.

Other places to check, depending on the task — these follow a pattern, so
don't treat the examples below as an exhaustive list if a contract
has grown since:

- [`plugins/README.md`](../../../plugins/README.md) — the list of
  first-party plugins and their backing libraries. Add a row here when
  adding a new plugin.
- `plugins/*.schema.json` (currently
  [`result.schema.json`](../../../plugins/result.schema.json),
  [`remote-result.schema.json`](../../../plugins/remote-result.schema.json),
  [`security-result.schema.json`](../../../plugins/security-result.schema.json),
  and
  [`supported-components-result.schema.json`](../../../plugins/supported-components-result.schema.json))
  — one machine-readable JSON Schema per bomify-parsed JSON shape a
  contract defines. SBOM generation is the one class with no schema
  here at all, since bomify never parses its output (a regular
  CycloneDX document, validated against CycloneDX's own schema
  instead). Glob for the current set rather than assuming these four
  are the only ones. Update the matching schema file whenever a result
  shape changes, and add a new one if a contract grows a new JSON
  shape.
- [`pkg/plugin`](../../../pkg/plugin) — the Go library implementing the
  Go-facing side of any contract bomify itself parses JSON from:
  importable from any Go module, one struct/type + `Print` method per
  JSON shape (`Result`/`Hash`/`RemoteResult` for the component contract,
  `SecurityResult`/`SupportedComponentsResult` for the security scanning
  contract), plus `OpenLog` for a component plugin's `--log`. Check the
  package itself for its current exported symbols rather than trusting a
  memorized list — a Go-based plugin, first- or third-party, should use
  these instead of hand-rolling JSON encoding or log setup. Nothing
  comparable exists for SBOM generation plugins, by design.
- [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) — how all three plugin
  contracts fit into bomify's design as a whole.

## Workflow

1. Read the relevant contract file in full before writing or changing
   plugin code — don't rely on memory or a summary of it. Read every
   subcommand's section, not just the ones you think are relevant; a
   flag-driven mode (like the component contract's `--check`) can change
   another subcommand's requirements (e.g. which flags are conditionally
   optional).
2. Implement/update the plugin to match it exactly: every subcommand the
   contract currently defines, its flags and modes, and the JSON result
   shape(s) it must print — an exact structured shape for the component
   and security scanning contracts (`Result`/`RemoteResult`, or
   `SecurityResult`/`SupportedComponentsResult` respectively), free-form
   (by convention a CycloneDX document) for SBOM generation only.
3. If the change is a breaking change or adds a new requirement to a
   contract itself, update `COMPONENT-CONTRACT.md`, `SBOM-CONTRACT.md`,
   or `SECURITY-CONTRACT.md` (and any `plugins/*.schema.json` whose
   shape changed, adding a new one if it grew a new JSON shape) in the
   same pass, and verify every existing first-party plugin under
   `plugins/` still conforms.
4. If adding a new plugin, add it to the table in `plugins/README.md`.

See also [AGENTS.md](../../../AGENTS.md) for the repo-wide rules this skill
supports.
