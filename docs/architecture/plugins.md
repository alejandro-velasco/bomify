# Plugins

A plugin binary can implement any of four independent contracts:

| Contract | Subcommands | Used by | `<kind>` names |
| --- | --- | --- | --- |
| [Component](https://github.com/alejandro-velasco/bomify/blob/main/plugins/COMPONENT-CONTRACT.md) | `component pull/push/remote` | `build`, `distribute` | a purl type |
| [SBOM generation](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SBOM-CONTRACT.md) | `sbom generate` | `sbom generate` | a deployment medium |
| [Security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SECURITY-CONTRACT.md) | `security scan/supported-components` | `security scan`, scan on pull | a scanner |
| [Signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/SIGNING-CONTRACT.md) | `signature sign/attest/verify/supported-types` | `--sign`, `--verify` | a signing scheme |

Every call bomify makes to a plugin goes through `plugin.Invoke`: run
the binary, parse stdout as the contract's JSON result, and fold stderr
into the error on failure. On the plugin side, `pkg/plugin`'s
`ComponentCommand`, `SecurityCommand`, and `SignatureCommand` build each
contract's subcommands (flags, validation, logging, output) around a
small Go interface, so a first-party plugin's `cmd` package is only an
adapter over its `internal` logic.

## Component plugins

For each SBOM component, `bomify build` and `bomify distribute`:

1. **Detect** the kind from the purl type (`plugin.Detect`):
   `pkg:oci/...` is `oci`. A missing or unparseable purl fails.
2. **Find** `bomify-plugin-<kind>` in `plugins/`. The exception is
   `pkg:bomify-plugin/...`: a plugin binary itself, which `build` copies
   directly (see [Plugin installation](plugin-installation.md)) and
   `distribute` skips.
3. **Delegate**: `component pull --purl --output` or `component push
   --purl --input --remote`. The plugin prints one JSON `{outputPath,
   message, hash}`, where `hash` is the SHA-256 of what it pulled.
   `distribute` first calls `component remote` to learn the component's
   origin, then picks the destination: `--remote <kind>=<endpoint>`,
   else the best `conf/distribution.json` rule matching that origin
   ([`internal/distribution`](https://github.com/alejandro-velasco/bomify/tree/main/internal/distribution)).

stdout is reserved for the result and stderr for one fatal message.
Plugins log to `--log`, `logs/<purlHash>.log`, which bomify creates
fresh before each call, streams to its own stdout under `--verbose`
(prefixed `[<verb> <purl>]`), and deletes afterwards. `--log-color`
passes on whether bomify's stdout is a terminal.

`--check` on `build`/`distribute` passes `--check=true` instead of
`--output`/`--input`, asking the plugin to cheaply confirm the transfer
would succeed. `plugin.CheckPull`/`CheckPush` are stateless: no pid
file, manifest, or layer directory, and `build --check` records no build.

![Plugin dispatch sequence](../diagrams/plugin-dispatch.svg)

*Source: [`docs/diagrams/plugin-dispatch.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/plugin-dispatch.mmd)*

## SBOM generation

`bomify sbom generate <kind> [flags]` finds `bomify-plugin-<kind>`, runs
its `sbom generate` with the flags unparsed, wires stdin/stdout/stderr
straight through, and propagates the exit code. That's all: no JSON
result, log file, or caching, so the plugin works exactly the same run
directly.

## Concurrent, idempotent pulls

`plugin.Pull` is safe to call concurrently, even across processes, for
components sharing a purl hash:

- `manifests/<purlHash>.pid` holds the PID of the process pulling it. A
  second caller waits until the file is gone or its process is dead.
- A stale pid file (process gone) is discarded and the pull redone.
- If a manifest exists and nothing is pulling, the result is reused. A
  reused or fresh result is always checked against the SBOM's declared
  hash, so a same-purl component with a different hash never slips
  through.
