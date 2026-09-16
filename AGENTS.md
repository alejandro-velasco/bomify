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

## Regenerate the CLI reference after flag/arg changes

[docs/reference/](docs/reference) is generated, not hand-written. Any time a
change touches a command's flags, arguments, or `Short`/`Long` description,
run `make docs` in the same pass and commit the regenerated files — never
hand-edit anything under `docs/reference/`.

## Keep README.md current

[README.md](README.md) should stay high level: how to run the tool and its
main features. If a change affects either of those, update README.md in the
same pass — but don't let it grow into a place for implementation detail;
that belongs in ARCHITECTURE.md or the relevant plugins doc instead.

## Keep plugin docs current

- Keep [plugins/README.md](plugins/README.md) current if making any high
  level changes to plugins, affecting their main features.
- Keep [plugins/CONTRACT.md](plugins/CONTRACT.md) current if making any
  breaking changes or adding new requirements to the contract.
- Always update [plugins/result.schema.json](plugins/result.schema.json) if
  updating the plugin result schema.
- If breaking changes or updates are made to the plugins, ensure the
  plugins still abide by the plugin contract.
