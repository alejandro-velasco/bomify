# SBOM generation plugin contract v1

A plugin reports the contract versions it speaks with
`bomify-plugin-<kind> contract` (see
[contract versions](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)).

The spec for a `bomify-plugin-<kind>` binary's **SBOM generation**
subcommand, `sbom generate`. Here `<kind>` names a
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

`bomify sbom compose`, merging several sources' SBOMs into one, writes
each source's options to a JSON file and runs `sbom generate --config
<file>` with the composition file's directory as the working directory
and stdin closed. It reads the SBOM from stdout, rejecting fields
cyclonedx-go doesn't know, and checks it against the rules below.

bomify does no caching or concurrency control around a generation.
Don't depend on the binary's other contracts, if it has any.

## Commands

### `sbom generate`

| Flag | Meaning |
| --- | --- |
| `--config <file>` | The options, a JSON object whose keys are the plugin's to define. Relative paths in it are relative to the working directory. Reject unknown keys, so a typo fails rather than being ignored. |

Any other flags are the plugin's own, for running it directly; document
them in `--help`, and use the same names as the options' keys, so its
`--help` documents both. With `--config`, never read stdin or prompt.

## Output

On success, print the SBOM to stdout as one CycloneDX JSON document,
spec version 1.5 or later, and exit `0`. On failure, exit non-zero;
stderr is free for logs and the error. Nothing else may go to stdout.

The SBOM is the part of a CycloneDX BOM bomify reads, each object
CycloneDX's own, following these rules.
[`generate-output.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/generate-output.schema.json)
expresses them, referencing
[CycloneDX's schema](https://cyclonedx.org/schema/bom-1.7.schema.json)
for the objects rather than restating it. bomify reads the SBOM with
[cyclonedx-go](https://github.com/CycloneDX/cyclonedx-go), rejecting
fields it doesn't know.

1. Only `metadata`, `components`, and `dependencies`, besides
   `bomFormat`, `specVersion`, `$schema`, and `version`: nothing else
   would survive merging with other SBOMs.
2. `metadata.component` describes what was generated from (e.g. the
   chart), with a `name`, a `version`, and a `purl`.
3. Every component, `metadata.component` included, has a `name` and a
   `purl`, and its `bom-ref` is that purl. Everything to package is in
   the top-level `components`, with unique `bom-ref`s. That includes
   what `metadata.component` describes, if it's to be packaged too, so
   the two share a `bom-ref`.
4. No component has nested `components`: `bomify build` only packages
   top-level ones.
5. Every `dependencies` entry's `ref` and `dependsOn` names a `bom-ref`
   in the document.
6. No `serialNumber` or `metadata.timestamp`: the same options and the
   same upstream content produce the same document, so a composed SBOM,
   and the package built from it, only changes when its content does.
