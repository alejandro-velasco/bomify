---
name: bomify-plugins
description: Use when writing, reviewing, or modifying a bomify-plugin-<kind> binary — implementing pull/push, its flags, Result JSON, hashing, or logging. Points to the authoritative spec rather than restating it.
---

# bomify plugins

A `bomify-plugin-<kind>` is a standalone executable bomify shells out to for
`pull`/`push` of one purl type. The full subprocess contract — naming and
discovery, the `pull`/`push` flags, stdout/stderr/exit-code rules, the
`Result` JSON shape, hash algorithm names, logging via `--log`, and what a
plugin does *not* need to handle — is specified in
[`plugins/CONTRACT.md`](../../../plugins/CONTRACT.md). Treat it as
authoritative; do not re-derive or paraphrase the contract here or in code
comments — read it directly before implementing or changing plugin
behavior.

Other places to check, depending on the task:

- [`plugins/README.md`](../../../plugins/README.md) — the list of
  first-party plugins and their backing libraries. Add a row here when
  adding a new plugin.
- [`plugins/result.schema.json`](../../../plugins/result.schema.json) — the
  machine-readable JSON Schema for the `Result` object. Update it alongside
  `CONTRACT.md` if the result shape changes.
- [`pkg/plugin`](../../../pkg/plugin) — the Go library implementing this
  contract's Go-facing side (`plugin.Result`, `plugin.Hash`,
  `plugin.OpenLog`, `(*Result).Print`), importable from any Go module. A
  Go-based plugin — first- or third-party — should use these helpers
  instead of hand-rolling JSON encoding or log setup.
- [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) — how the plugin contract
  fits into bomify's design as a whole.

## Workflow

1. Read `CONTRACT.md` in full before writing or changing plugin code —
   don't rely on memory or a summary of it.
2. Implement/update the plugin to match it exactly (flags, streams, exit
   codes, `Result` fields).
3. If the change is a breaking change or adds a new requirement to the
   contract itself, update `CONTRACT.md` (and `result.schema.json` if the
   result shape changed) in the same pass, and verify every existing
   first-party plugin under `plugins/` still conforms.
4. If adding a new plugin, add it to the table in `plugins/README.md`.

See also [AGENTS.md](../../../AGENTS.md) for the repo-wide rules this skill
supports.
