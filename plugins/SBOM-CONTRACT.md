# SBOM generation plugin contract

The spec for a `bomify-plugin-<kind>` binary's **SBOM generation**
subcommand, `sbom generate`, which `bomify sbom generate <kind> [flags]`
calls. It's independent of the
[component](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md),
[security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SECURITY-CONTRACT.md),
and [signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SIGNING-CONTRACT.md)
contracts. Here `<kind>` names a deployment medium (e.g. `helm`, `oci`).

## Naming and discovery

As for the [component contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md#naming-and-discovery):
`bomify-plugin-<kind>` (`.exe` on Windows), installed in
`<data-dir>/plugins`.

## What bomify does

bomify finds the plugin and runs

```
bomify-plugin-<kind> sbom generate [flags]
```

with `flags` passed through unchanged, stdin/stdout/stderr wired to its
own, and the plugin's exit code as its own. It parses nothing, adds no
flags, and keeps no state, so running the plugin directly is exactly
equivalent.

## Commands

`sbom generate` is the only subcommand, and its flags are entirely up to
the plugin (no `--purl`, `--log`, or `--check`). Document them in
`--help`.

## Output

stdout, stderr, and the exit code are the plugin's to use as it likes,
including prompts and progress. The one convention: **on success, print
the SBOM as CycloneDX JSON to stdout**, so `bomify sbom generate <kind>
... > out.cdx.json` works. There's no bomify-specific wrapper or schema;
validate against [CycloneDX's own](https://cyclonedx.org/docs/).

bomify does no caching, concurrency control, or checks around a
generation. Don't depend on the binary's other contracts, if it has any.
