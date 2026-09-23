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

## The docs site (`docsite/`)

[`docsite/`](docsite) is a [Zensical](https://zensical.org) site published to
GitHub Pages (`.github/workflows/docs-site.yml`). Several of its pages
source from a doc that lives elsewhere in the repo — never hand-edit any
of them into a second, separately-worded copy of the same content:

- `usage/reference/` is a copy of [`docs/reference/`](docs/reference),
  made by `make docs-site`/`docs-site-sync` — regenerate the source with
  `make docs`, as already documented above, and re-run `docs-site-sync`
  to pick it up. Never hand-edit files under `usage/reference/` directly.
- `getting-started/installing-plugins.md`, `development/contract.md`, and
  `development/sbom-contract.md` are thin wrapper pages (front matter for
  a nav icon, plus one line) that include
  [`plugins/README.md`](plugins/README.md),
  [`plugins/CONTRACT.md`](plugins/CONTRACT.md), and
  [`plugins/SBOM-CONTRACT.md`](plugins/SBOM-CONTRACT.md) live via a
  `pymdownx.snippets` directive (e.g. `--8<-- "plugins/README.md"`,
  resolved against the `base_path` set in `docsite/zensical.toml`) rather
  than a copy — edit the source files themselves, never the wrapper
  pages. Keep their links absolute GitHub URLs, not repo-relative, since
  the include is rendered from a different directory than the original
  file (`docsite/docs/development/building-a-plugin.md` is the one place
  it's correct to link to `contract.md`/`sbom-contract.md` in-site
  instead, since those pages only exist inside `docsite/`).

The one part of `docsite/` that does need hand-maintenance is the command
list in [`docsite/zensical.toml`](docsite/zensical.toml)'s `nav` — update it
when a command is added, removed, or renamed. Everything else under
`docsite/docs/` is hand-written prose; keep it pointing at (not copying)
`ARCHITECTURE.md`, `plugins/CONTRACT.md`, etc. the same way it does today,
rather than restating their content.

## Keep README.md current

[README.md](README.md) should stay high level: how to run the tool and its
main features. If a change affects either of those, update README.md in the
same pass — but don't let it grow into a place for implementation detail;
that belongs in ARCHITECTURE.md or the relevant plugins doc instead.

## Opening pull requests

When a PR needs to be written for this repo:

- Use [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) as
  the body — fill in its sections rather than writing an ad hoc description.
- Title the PR in Conventional Commits style (`<type>[(scope)]: <description>`),
  with the type and scope matching the actual scope of the code change.
- Never merge the PR. Always stop once it's opened and leave merging to a
  human.

## Keep plugin docs current

bomify's plugin contract is actually two entirely independent contracts a
`bomify-plugin-<kind>` binary can implement — the **component plugin**
contract (`component pull`/`component push`/`component remote`) and the
**SBOM generation plugin** contract (`sbom generate`). Keep whichever
you're changing current, and never let a change to one imply the other:

- Keep [plugins/README.md](plugins/README.md) current if making any high
  level changes to plugins, affecting their main features.
- Keep [plugins/CONTRACT.md](plugins/CONTRACT.md) current if making any
  breaking changes or adding new requirements to the component contract.
- Keep [plugins/SBOM-CONTRACT.md](plugins/SBOM-CONTRACT.md) current if
  making any breaking changes or adding new requirements to the SBOM
  generation contract.
- Always update [plugins/result.schema.json](plugins/result.schema.json) if
  updating the component plugin result schema (SBOM generation plugins
  have no bomify-specific result schema — see SBOM-CONTRACT.md).
- If breaking changes or updates are made to the plugins, ensure the
  plugins still abide by whichever plugin contract(s) they implement.
