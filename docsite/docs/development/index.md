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
- [**`plugins/COMPONENT-CONTRACT.md`**](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md) —
  the authoritative **component plugin** subprocess contract
  (`component pull`/`component push`/`component remote`); see
  [Building a plugin](building-a-plugin.md) for a guided walkthrough of it.
- [**`plugins/SBOM-CONTRACT.md`**](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md) —
  the authoritative **SBOM generation plugin** subprocess contract
  (`sbom generate`), entirely independent of the component contract above.
