---
icon: lucide/hammer
---

# Development

This section is for people working on bomify itself, or on a plugin for it —
not for people just using the CLI (see [Getting started](../getting-started/index.md)
and [Usage](../usage/index.md) for that).

- [Building a plugin](building-a-plugin.md) — writing a new
  `bomify-plugin-<kind>` binary, first- or third-party.
- [**`ARCHITECTURE.md`**](https://github.com/alejandro-velasco/bomify/blob/main/ARCHITECTURE.md) —
  how bomify is put together internally: the on-disk data directory, plugin
  dispatch, build/tag bookkeeping, push/pull, save/load, and credentials.
  Aimed at anyone modifying bomify itself.
- [**`AGENTS.md`**](https://github.com/alejandro-velasco/bomify/blob/main/AGENTS.md) —
  repo-wide conventions for contributors (and AI coding agents) working in
  this codebase: what's generated vs. hand-written, PR conventions, and
  where each kind of documentation belongs.
- [**`plugins/CONTRACT.md`**](https://github.com/alejandro-velasco/bomify/blob/main/plugins/CONTRACT.md) —
  the authoritative plugin subprocess contract; see
  [Building a plugin](building-a-plugin.md) for a guided walkthrough of it.
