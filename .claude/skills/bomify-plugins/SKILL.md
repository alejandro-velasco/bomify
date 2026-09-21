---
name: bomify-plugins
description: Use when writing, reviewing, or modifying a bomify-plugin-<kind> binary — its subcommands, flags, JSON result shapes, hashing, or logging. Points to the authoritative spec rather than restating it.
---

# bomify plugins

A `bomify-plugin-<kind>` is a standalone executable bomify shells out to for
every operation on one purl type. The full subprocess contract — naming and
discovery, every subcommand and its flags, stdout/stderr/exit-code rules,
each JSON result shape, hash algorithm names, logging via `--log`, and what
a plugin does *not* need to handle — is specified in
[`plugins/CONTRACT.md`](../../../plugins/CONTRACT.md). Treat it as
authoritative; do not re-derive or paraphrase the contract here or in code
comments — read it directly, in full, before implementing or changing
plugin behavior. Don't assume the contract is just `pull`/`push`, or that a
subcommand's flags/behavior stop at whatever an older skim or memory of it
suggested — re-read `CONTRACT.md` itself; it has grown subcommands (`remote`)
and flag-driven modes (`--check`) before and will likely again.

Other places to check, depending on the task — these follow a pattern, so
don't treat the examples below as an exhaustive list if `CONTRACT.md` has
grown since:

- [`plugins/README.md`](../../../plugins/README.md) — the list of
  first-party plugins and their backing libraries. Add a row here when
  adding a new plugin.
- `plugins/*.schema.json` (currently
  [`result.schema.json`](../../../plugins/result.schema.json) and
  [`remote-result.schema.json`](../../../plugins/remote-result.schema.json))
  — one machine-readable JSON Schema per JSON shape the contract defines.
  Glob for the current set rather than assuming these two are the only
  ones. Update the matching schema file alongside `CONTRACT.md` whenever a
  result shape changes, and add a new one if `CONTRACT.md` grows a new JSON
  shape.
- [`pkg/plugin`](../../../pkg/plugin) — the Go library implementing the
  contract's Go-facing side: importable from any Go module, one struct +
  `Print` method per JSON shape (e.g. `Result`/`Hash`, `RemoteResult`),
  plus `OpenLog` for `--log`. Check the package itself for its current
  exported symbols rather than trusting a memorized list — a Go-based
  plugin, first- or third-party, should use these instead of hand-rolling
  JSON encoding or log setup.
- [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) — how the plugin contract
  fits into bomify's design as a whole.

## Workflow

1. Read `CONTRACT.md` in full before writing or changing plugin code —
   don't rely on memory or a summary of it. Read every subcommand's
   section, not just the ones you think are relevant; a flag-driven mode
   (like `--check`) can change another subcommand's requirements (e.g.
   which flags are conditionally optional).
2. Implement/update the plugin to match it exactly: every subcommand
   `CONTRACT.md` currently defines, its flags and modes, and the JSON
   result shape(s) it must print.
3. If the change is a breaking change or adds a new requirement to the
   contract itself, update `CONTRACT.md` (and any `plugins/*.schema.json`
   whose shape changed, adding a new one if the contract grew a new JSON
   shape) in the same pass, and verify every existing first-party plugin
   under `plugins/` still conforms.
4. If adding a new plugin, add it to the table in `plugins/README.md`.

See also [AGENTS.md](../../../AGENTS.md) for the repo-wide rules this skill
supports.
