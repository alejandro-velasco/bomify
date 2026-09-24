# SBOM generation plugin contract

This is the specification for the subprocess contract between `bomify`
and a `bomify-plugin-<kind>` binary's **SBOM generation** subcommand,
`sbom generate`, which `bomify sbom generate <kind> [flags]` delegates
to. It's an entirely independent contract from the [component plugin
contract](COMPONENT-CONTRACT.md) (`component pull`/`component push`/`component
remote`, which `bomify build`/`bomify distribute` use) and the
[security scanning plugin contract](SECURITY-CONTRACT.md) (`security
scan`) — a plugin binary may implement any, all, or none of the three,
and implementing one owes nothing to the others. `<kind>` here names a
deployment medium (e.g. `helm`, `oci`) rather than a purl type, but
follows the same naming and discovery rules.

## Naming and discovery

Identical to the [component contract's](COMPONENT-CONTRACT.md#naming-and-discovery):
a plugin for medium `<kind>` must be named exactly `bomify-plugin-<kind>`
(`bomify-plugin-<kind>.exe` on Windows) and discoverable on `PATH`.
`bomify sbom generate <kind> ...` looks up `bomify-plugin-<kind>` the
same way `bomify build`/`bomify distribute` look up a component plugin,
and never invokes it by any other name or location.

## What bomify does

`bomify sbom generate <kind> [flags]` is a pure delegator: it locates
`bomify-plugin-<kind>` on `PATH` and execs it as

```
bomify-plugin-<kind> sbom generate [flags]
```

with `flags` passed through completely unchanged, and the plugin's
stdin, stdout, and stderr wired directly to bomify's own. bomify does
not parse, capture, or otherwise interpret anything the plugin prints,
does not impose any flags of its own (no `--purl`, `--log`,
`--log-color`, `--check`, or anything else the component contract
requires), and keeps no cache, manifest, or other state around a
generation. The plugin's exit code is bomify's own exit code.

This makes a plugin's `sbom generate` fully standalone: running

```
bomify-plugin-<kind> sbom generate [flags]
```

directly is, by design, exactly equivalent to running it through
`bomify sbom generate <kind> [flags]` — bomify contributes nothing to
the operation beyond locating the binary.

## Commands

An SBOM generation plugin must implement exactly one subcommand,
nested under `sbom`:

```
bomify-plugin-<kind> sbom generate [flags]
```

Unlike the component contract, `flags` is entirely up to the plugin —
bomify prescribes none. Document your own flags in your plugin's
`--help`/README; the orchestrator example above
(`--chart`/`--repo`/`--version`/`--values` for a Helm plugin) is
illustrative, not normative.

## Standard streams

A plugin is free to use stdout, stderr, and its exit code however suits
it — including interactive prompts, progress output, or `--help` text —
since bomify streams all three straight through rather than parsing
anything, unlike the component contract's strict stdout-is-JSON-only
rule.

The one convention (not enforced by bomify, but expected by anything
downstream of `bomify sbom generate`) is: **on success, print the
generated SBOM as CycloneDX JSON to stdout**, so
`bomify sbom generate <kind> [flags] > out.cdx.json` behaves
predictably. There is no bomify-specific JSON envelope around it — no
new `plugins/*.schema.json` describes this shape, since it's just a
regular CycloneDX document. Validate your plugin's actual output
against [CycloneDX's own schema](https://cyclonedx.org/docs/) instead.

## Logging

There is no `--log`/`--log-color` flag here, and no reason for one: since
bomify never captures or streams anything on the plugin's behalf, a
plugin is free to log however it likes, straight to its own stderr if it
wants to.

## What a plugin does *not* need to handle

- No `--purl` — a deployment medium isn't necessarily addressed by a
  purl, and the plugin defines whatever flags it needs to identify what
  to inspect.
- No `--check` mode, caching, or concurrency control — bomify does none
  of that for `sbom generate`; every invocation is a fresh, independent
  process bomify neither dedupes nor tracks.
- No coordination with this binary's own component plugin subcommands
  (if it has any) — the two contracts must not depend on each other's
  behavior or state.
