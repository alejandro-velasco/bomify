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
- Go into detail only in reference material: ARCHITECTURE.md for
  internals, the plugin contracts for plugin authors.
- A command's `Long` text covers what it does and non-obvious flag
  interactions; the docs site covers workflows.

## Keep docs in sync with code

In the same change that makes a doc inaccurate:

- **ARCHITECTURE.md**: update it for changes to the data directory,
  plugin architecture, build/tag bookkeeping, push/pull, save/load, or
  credentials.
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
- `getting-started/installing-plugins.md` and
  `development/{component,sbom,security,signing}-contract.md` are
  one-line wrappers that include `plugins/README.md` and the
  `plugins/*-CONTRACT.md` files via `pymdownx.snippets`. Edit the
  sources, and keep links in them absolute GitHub URLs, since they
  render from a different directory. (`development/building-a-plugin.md`
  may link to the in-site contract pages.)

Update the command list in `docsite/zensical.toml`'s `nav` when a
command is added, removed, or renamed. Everything else in
`docsite/docs/` is hand-written; link to ARCHITECTURE.md and the
contracts rather than restating them.

## Opening pull requests

- Fill in [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md).
- Title it in Conventional Commits style (`<type>[(scope)]: <description>`),
  matching the change's actual scope.
- Never merge it; leave that to a human.
