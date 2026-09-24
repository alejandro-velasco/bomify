# Security scanning plugin contract

This is the specification for the subprocess contract between `bomify`
and a `bomify-plugin-<type>` binary's **security scanning** subcommands,
`security scan` and `security supported-components`, which `bomify
security scan <type> <sbom-file>` delegates to — the latter once, the
former once per (supported) component in the SBOM, concurrently. It's an
entirely independent contract from the
[component plugin contract](COMPONENT-CONTRACT.md) and the
[SBOM generation plugin contract](SBOM-CONTRACT.md) — a plugin binary
may implement any, all, or none of the three, and implementing one owes
nothing to the others.

`<type>` here is different from `<kind>` in the other two contracts: it
names the **scanning tool itself** (e.g. `grype`, `trivy`), not a purl
type or a deployment medium. Any scanner can in principle scan any
component regardless of its purl type, so `<type>` identifies *which
engine* to run — the same one, for every component in the SBOM — not
*what's being scanned*.

## Naming and discovery

Identical to the [component contract's](COMPONENT-CONTRACT.md#naming-and-discovery):
a plugin for scanning tool `<type>` must be named exactly
`bomify-plugin-<type>` (`bomify-plugin-<type>.exe` on Windows) and
discoverable on `PATH`. `bomify security scan <type> ...` looks up
`bomify-plugin-<type>` the same way `bomify build`/`bomify distribute`
look up a component plugin, and never invokes it by any other name or
location.

## What bomify does

Unlike the SBOM generation contract, bomify does real orchestration
work here, much closer to the component contract's `pull`/`push`
dispatch:

1. **Load** `<sbom-file>` itself and walk every component it describes.
2. **Find** `bomify-plugin-<type>` on `PATH` once — the same binary
   scans every component, regardless of purl type.
3. **Query** that binary's `security supported-components` once, to
   learn which component purl types and scan categories it supports —
   see [SupportedComponentsResult](#supportedcomponentsresult). A
   component whose purl type isn't in the reported list is skipped
   entirely; it's never sent to `security scan` at all.
4. **Delegate**, once per remaining component, up to `--concurrency` at
   a time (mirroring `bomify build`/`bomify distribute`'s own flag):
   call `security scan --purl <purl>` and parse its JSON result.
5. **Merge** every component's result into one deduplicated
   vulnerability list — see [Merging](#merging) — and write it back
   into the SBOM's `vulnerabilities`, printing the result to stdout (or
   `--output`'s file).

A plugin never opens `<sbom-file>` itself, and `security scan` never
sees any component but the one named by the `--purl` it was given for
that invocation — bomify owns the SBOM, the dispatch, the concurrency,
and the merge.

## Commands

A security scanning plugin must implement exactly two subcommands,
nested under `security`:

```
bomify-plugin-<type> security scan --purl <purl>
bomify-plugin-<type> security supported-components
```

### `security scan`

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | *The component's package URL. The plugin derives everything it needs to know about what to scan from this string.* |

On success, the plugin must print a single `SecurityResult` JSON array
(see [SecurityResult](#securityresult)) to stdout and exit `0`.

### `security supported-components`

Takes no flags. Reports which component purl types and scan categories
this plugin supports — bomify calls this once per `bomify security
scan` invocation, never once per component, to decide which components
are even worth dispatching to `security scan` (step 3 above).

On success, the plugin must print a single `SupportedComponentsResult`
JSON object (see [SupportedComponentsResult](#supportedcomponentsresult))
to stdout and exit `0`. It must be a pure function of nothing at all —
the same plugin binary always reports the same capabilities.

Unlike the component contract, neither subcommand takes `--output`/
`--input`, `--hash`, `--check`, or `--log`/`--log-color` — a security
scanning plugin only ever answers "what does this purl have" and "what
do you support", nothing else. Routine logging is the plugin's own
business; write it straight to stderr if you want it, there's no
`--log` file to route it through.

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one JSON value, printed only on success — a `SecurityResult` array for `scan`, a `SupportedComponentsResult` object for `supported-components`. Nothing else may ever be written here — no progress output, no debug prints, nothing. bomify parses stdout as JSON and fails accordingly (that component's scan, or the whole invocation for `supported-components`) if it isn't exactly that. |
| stderr | A single, short, human-readable fatal error message, written only on failure (non-zero exit). bomify captures this and appends it verbatim to the error it reports; a single component's `scan` failure fails the whole `bomify security scan`, exactly like a failed `pull` fails the whole `bomify build` — and a failing `supported-components` call fails it before any component is even scanned. Like stdout, this is not a place for routine logging — though unlike the component contract, there's no `--log` file to route logging through instead, so a plugin may write its own diagnostics to stderr directly as long as nothing but the one fatal message appears there on failure. |
| exit code | `0` on success (with valid JSON on stdout). Any non-zero value on failure. |

## SecurityResult

The single JSON array a plugin prints to stdout on success: every
CycloneDX vulnerability the scanned `--purl` is affected by.

```json
[
  {
    "bom-ref": "CVE-2024-12345",
    "id": "CVE-2024-12345",
    "description": "...",
    "ratings": [{ "severity": "high" }]
  }
]
```

An empty array (`[]`) reports that nothing was found — just as
meaningful a result as a populated one, and not an error.

Each entry is a regular [CycloneDX `vulnerability`](https://cyclonedx.org/docs/)
object; there is no bomify-specific field beyond the array wrapper
itself. **Leave `affects` unset.** bomify sets it itself, to the
component currently being scanned, before merging — see
[Merging](#merging) below for exactly why and how. Setting a stable
`bom-ref` per vulnerability (the vulnerability's own ID is a reasonable
choice) is what makes that merge meaningful: without one, the same
vulnerability reported by two different components can't be recognized
as the same finding, and ends up duplicated in the output instead of
merged.

A machine-readable version of this schema is published at
[`security-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/security-result.schema.json).

Go plugins should build this as a `plugin.SecurityResult` (see
[`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)) and print it with `(SecurityResult).Print`,
rather than hand-rolling the JSON encoding.

## SupportedComponentsResult

The single JSON object a plugin's `security supported-components`
subcommand prints to stdout on success:

```json
{
  "types": ["oci", "helm", "generic"],
  "scans": ["sca"]
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `types` | array of strings | yes, non-empty | Every component purl type (e.g. `oci`, `helm`, `npm`, `generic` — the same names `plugin.Detect` derives from a purl) this plugin knows how to scan. A component whose purl type isn't in this list is never sent to `security scan`. |
| `scans` | array of strings | yes | The categories of scan this plugin performs, e.g. `sca` (software composition analysis), `sast` (static analysis). Purely informational today — bomify logs it, but doesn't yet act on it — so use whatever names are meaningful for your plugin. |

A machine-readable version of this schema is published at
[`supported-components-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/supported-components-result.schema.json).

Go plugins should build this as a `plugin.SupportedComponentsResult`
(see [`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)) and print it with
`(*SupportedComponentsResult).Print`, rather than hand-rolling the JSON
encoding.

## Merging

Once every component has been scanned, bomify combines their results
into the SBOM's own `vulnerabilities` array:

1. For each vulnerability a component's scan reported, bomify sets its
   `affects` to that one component — by `bom-ref` if the component has
   one, falling back to its purl if it doesn't.
2. If a vulnerability with the same (non-empty) `bom-ref` has already
   been collected from a different component, the two are merged: the
   new one's `affects` entry is added to the existing entry's `affects`
   instead of appending a whole second, duplicate vulnerability.
3. A vulnerability with no `bom-ref` at all is never merged with
   anything — it's kept as its own distinct entry, since there'd be no
   reliable way to tell it apart from an unrelated finding that also
   happened to omit one.

This is entirely bomify's responsibility; a plugin never sees another
component's result and has no say in how (or whether) its own findings
get merged with theirs.

## What a plugin does *not* need to handle

- No `--check` mode, caching, or concurrency control of its own —
  bomify owns concurrency (`--concurrency`) and invokes `security scan`
  fresh for every component; a plugin never needs to remember anything
  between invocations or deduplicate anything itself.
- No filtering of components by type — bomify does that itself, using
  `security supported-components`'s answer, before ever calling
  `security scan`; a plugin doesn't need to validate or reject a purl
  type it doesn't support, since it will simply never be asked about
  one.
- No knowledge of the SBOM it came from, `affects`, or any other
  component's result — bomify assembles all of that afterward.
- No coordination with this binary's own component or SBOM generation
  subcommands (if it has any) — the three contracts must not depend on
  each other's behavior or state.

`security scan` should be a pure function of `--purl`: given the same
one, do the same thing. `security supported-components` should be a
pure function of nothing at all.
