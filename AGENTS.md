# AGENTS.md

Instructions for AI coding agents working in this repository.

## Load local skills

Before starting, load any local skills in `.claude/skills/`,
`.github/skills/`, and `skills/`. They take precedence over generic
defaults.

## Writing documentation

Keep every doc, command description, and code comment tight:

- Say each thing once, where it belongs, and link to it elsewhere.
- Lead with what the reader needs; add rationale only where a choice
  isn't obvious.
- Go into detail only in reference material: `docs/architecture/` for
  internals, the plugin contracts for plugin authors.
- A command's `Long` text covers what it does and non-obvious flag
  interactions; the docs site covers workflows.

## Keep docs in sync with code

In the same change that makes a doc inaccurate:

- **`docs/architecture/`**: update the matching page for changes to the
  data directory, plugins, build/tag bookkeeping, push/pull, save/load,
  or credentials.
- **Diagrams**: edit `docs/diagrams/*.mmd`, never the `.svg`, then run
  `make diagrams` and commit both.
- **CLI reference**: `docs/reference/` is generated. After changing a
  command's flags, arguments, or `Short`/`Long`, run `make docs` and
  commit the result; never hand-edit it.
- **README.md**: keep it to how to run the tool and its main features.
- **Plugin docs**: follow the `bomify-plugins` skill.

## The docs site (`docsite/`)

A [Zensical](https://zensical.org) site published to GitHub Pages
(`.github/workflows/docs-site.yml`). Some pages come from elsewhere;
never turn them into separate copies:

- `usage/reference/` is copied from `docs/reference/` by `make
  docs-site-sync`.
- `getting-started/installing-plugins.md`,
  `development/{component,sbom,security,signing}-contract.md`, and
  `development/architecture/*.md` are wrappers that include
  `plugins/README.md`, each contract's current
  `plugins/contracts/<contract>/v<N>/CONTRACT.md`, and
  `docs/architecture/*.md` via `pymdownx.snippets`. Edit the sources.
  The plugins and contract pages also include each of their
  `*.schema.json` files under "Schemas"; list a new schema there.
  Since they render from a different directory, links in them to other
  repo files must be absolute GitHub URLs. The exceptions: links between
  architecture pages, and their `../diagrams/*.svg` images, which `make
  docs-site-sync` copies to the same relative path. (Other docsite pages
  may link to the in-site contract and architecture pages.)
- A new architecture page needs a wrapper and a `nav` entry.

Update the command list in `docsite/zensical.toml`'s `nav` when a
command is added, removed, or renamed. Everything else in
`docsite/docs/` is hand-written; link to `docs/architecture/` and the
contracts rather than restating them.

## Opening pull requests

- Fill in [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).
- Title it in Conventional Commits style (`<type>[(scope)]: <description>`),
  matching the change's actual scope.
- Never merge it; leave that to a human.
