# Security scanning plugin contract v1

A plugin reports the contract versions it speaks with
`bomify-plugin-<type> contract` (see
[contract versions](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)).

The spec for a `bomify-plugin-<type>` binary's **security scanning**
subcommands, `security scan` and `security supported-components`, which
`bomify security scan <type> <tag>` (and a scan on `pull`/`load`) call.
It's independent of the
[component](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md),
[SBOM generation](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md),
and [signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)
contracts.

Here `<type>` names the scanning tool (e.g. `grype`, `trivy`), not a
purl type: one scanner handles every component in a package.

Go plugins should implement `pkg/plugin`'s `SecurityPlugin` interface and
use `plugin.SecurityCommand`, which provides both subcommands, their
flags, and output.

## Naming and discovery

As for the [component contract](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/CONTRACT.md#naming-and-discovery):
`bomify-plugin-<type>` (`.exe` on Windows), installed in
`<data-dir>/plugins`.

## What bomify does

1. Resolves `<tag>` to a local package and walks its SBOM.
2. Calls `security supported-components` once, and skips every component
   whose purl type isn't listed.
3. Calls `security scan --purl <purl>` once per remaining component, up
   to `--concurrency` at a time.
4. Writes each result as that component's [report](#reports).

The plugin never sees the SBOM or any component but the one it's asked
about.

## Commands

```
bomify-plugin-<type> security scan --purl <purl>
bomify-plugin-<type> security supported-components
```

- **`security scan`**: `--purl` (required) is the component to scan; the
  plugin derives everything from it. On success, print one
  [`SecurityResult`](#securityresult) and exit `0`.
- **`security supported-components`**: no flags. On success, print one
  [`SupportedComponentsResult`](#supportedcomponentsresult) and exit
  `0`. It must always report the same thing.

There's no `--check`, `--output`/`--input`, or `--log`/`--log-color`.

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one JSON result, only on success. Nothing else, ever. |
| stderr | Diagnostics are allowed, but on failure it must hold only one short fatal message, which bomify appends to its error. |
| exit code | `0` on success; non-zero on failure. |

A failed `scan` fails the whole `bomify security scan`, as a failed
`pull` fails `build`. A failed `supported-components` fails it before
anything is scanned.

## SecurityResult

```json
{
  "vulnerabilities": [
    {
      "bom-ref": "CVE-2024-12345",
      "id": "CVE-2024-12345",
      "ratings": [{ "severity": "high" }],
      "affects": [{ "ref": "pkg:npm/left-pad@1.3.0" }]
    }
  ],
  "components": []
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `vulnerabilities` | array | yes (may be empty) | Every CycloneDX `vulnerability` affecting `--purl`. Empty means nothing was found; that's a valid result, not an error. |
| `components` | array | no | CycloneDX `component`s the plugin unpacked `--purl` into to scan it (e.g. the packages inside an image). Omit if it scanned the purl directly. |

**The plugin sets `affects`; bomify never changes it.**

- Scanned directly: `affects` is one entry, the `--purl` given.
- Unpacked: `affects` names the affected pieces by their `bom-ref` from
  `components`, never the top-level purl. A vulnerability affecting
  several pieces lists them all in one object.

Give each vulnerability a stable `bom-ref` (its ID works) and each
component a stable `bom-ref` (its purl works). Report every piece you
unpacked, not just affected ones; bomify filters them.

Schema: [`security-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/security-result.schema.json).

## SupportedComponentsResult

```json
{ "types": ["oci", "helm", "generic"], "scans": ["sca"] }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `types` | array of strings | yes, non-empty | Purl types the plugin can scan (`oci`, `npm`, ...). Components of other types are never sent to `scan`. |
| `scans` | array of strings | yes | Scan categories (e.g. `sca`, `sast`). Informational: bomify only logs them. |

Schema: [`supported-components-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/supported-components-result.schema.json).

## Reports

bomify writes each result as a CycloneDX document at
`<data-dir>/vulnerabilities/<purl-hash>.json`:

- `metadata.component` is the scanned component, `bom-ref` set to its
  purl, so a directly scanned component's `affects` resolve.
- `components` are only the unpacked pieces some `affects` names.
- `vulnerabilities` are exactly what the plugin reported, unmodified.
- `metadata.timestamp` and `metadata.tools` record when and by which
  plugin it was scanned.

Reports are keyed by purl alone, so packages sharing a component share
its report, and the newest scan replaces it. On push or save, reports
travel as an OCI referrer, so re-scanning never changes the package
digest (see
[the architecture docs](https://github.com/alejandro-velasco/bomify/blob/main/docs/architecture/security-scanning.md#reports-in-a-registry)).

## What bomify handles

Concurrency, filtering by type, and storing results are bomify's job.
Each call is fresh, the plugin is never asked about an unsupported type,
and it needs no knowledge of the package or other components. Don't
depend on the binary's other contracts, if it has any.
