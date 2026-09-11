# AGENTS.md

Instructions for AI coding agents working in this repository.

## Load local skills

Before starting work, check for and load any local skills defined for this
repo: `.claude/skills/`, `.github/skills/`, and `skills/` (in that order,
wherever present). These encode project-specific workflows and take
precedence over generic defaults.

## Keep ARCHITECTURE.md current

After making a change, check whether it affects anything
[ARCHITECTURE.md](ARCHITECTURE.md) describes — the plugin architecture, the
data directory layout, build/tag bookkeeping, push/pull, save/load, or
credentials. If the change makes any part of that document inaccurate,
update ARCHITECTURE.md in the same pass rather than leaving it to go stale.

## Diagrams are Mermaid sources, not SVGs

ARCHITECTURE.md embeds diagrams as `.svg` files rendered from the Mermaid
sources under `docs/diagrams/*.mmd`. Never hand-edit an `.svg` directly:
edit the corresponding `.mmd` source, then regenerate every diagram with
`make diagrams`. Commit both the updated `.mmd` and its regenerated `.svg`.
