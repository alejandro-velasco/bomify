# SBOM generation plugin contract v1

A plugin reports the contract versions it speaks with
`bomify-plugin-<kind> contract` (see
[contract versions](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)).

The spec for a `bomify-plugin-<kind>` binary's **SBOM generation**
subcommands, `sbom schema` and `sbom generate`. Here `<kind>` names a
deployment medium (e.g. `helm`). It's independent of the
[component](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md),
[security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/CONTRACT.md),
and [signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)
contracts.

A Go plugin gets all of this from
[`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)'s
`SBOMCommand`, which also checks its own output against the rules below.

## Naming and discovery

As for the [component contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md#naming-and-discovery):
`bomify-plugin-<kind>` (`.exe` on Windows), installed in
`<data-dir>/plugins`.

## What bomify does

bomify calls a plugin two ways:

- **`bomify sbom compose`**, merging several sources' SBOMs into one:
  it validates each source's options against `sbom schema`, writes them
  to a JSON file, and runs `sbom generate --config <file>` with the
  composition file's directory as the working directory and stdin
  closed. It reads the SBOM from stdout and checks it against the rules
  below.
- **`bomify sbom generate <kind> [flags]`**: it runs `sbom generate`
  with `flags` passed through unchanged, stdin/stdout/stderr wired to its
  own, and the plugin's exit code as its own, so running the plugin
  directly is exactly equivalent.

bomify does no caching or concurrency control around a generation.
Don't depend on the binary's other contracts, if it has any.

## Commands

### `sbom schema`

No flags. Print the [JSON Schema](https://json-schema.org/) (2020-12) of
the options object `sbom generate --config` takes, and exit `0`. It must
always print the same thing. Reject unknown keys
(`"additionalProperties": false`), so a typo fails before anything runs.

### `sbom generate`

| Flag | Meaning |
| --- | --- |
| `--config <file>` | The options, a JSON object valid against `sbom schema`. Relative paths in it are relative to the working directory. |

Any other flags are the plugin's own, for running it directly; document
them in `--help`. With `--config`, never read stdin or prompt.

## Output

On success, print the SBOM to stdout as one CycloneDX JSON document,
spec version 1.5 or later, and exit `0`. On failure, exit non-zero;
stderr is free for logs and the error. Nothing else may go to stdout.

The SBOM must follow these rules, which
[`generate-output.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/generate-output.schema.json)
also expresses, alongside
[CycloneDX's own schema](https://cyclonedx.org/docs/):

1. `metadata.component` describes what was generated from (e.g. the
   chart), with a `name`, a `version`, and a `purl`.
2. Every component, `metadata.component` included, has a `name` and a
   `purl`, and its `bom-ref` is that purl. Everything to package is in
   the top-level `components`, with unique `bom-ref`s. That includes
   what `metadata.component` describes, if it's to be packaged too, so
   the two share a `bom-ref`.
3. No component has nested `components`: `bomify build` only packages
   top-level ones.
4. Every `dependencies` entry's `ref` and `dependsOn` names a `bom-ref`
   in the document.
5. No `serialNumber` or `metadata.timestamp`: the same options and the
   same upstream content produce the same document, so a composed SBOM,
   and the package built from it, only changes when its content does.
