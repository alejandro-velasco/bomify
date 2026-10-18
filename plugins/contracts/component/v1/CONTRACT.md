# Component plugin contract v1

A plugin reports the contract versions it speaks with
`bomify-plugin-<kind> contract` (see
[contract versions](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)).

The authoritative spec for a `bomify-plugin-<kind>` binary's **component
plugin** subcommand (`component pull`), which `bomify build` calls. It's
independent of the
[SBOM generation](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/sbom/v1/CONTRACT.md),
[security scanning](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/security/v1/CONTRACT.md),
and [signing](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/signing/v1/CONTRACT.md)
contracts; a binary can implement any combination.

Go plugins should use
[`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin):
implement its `ComponentPlugin` interface and `plugin.ComponentCommand`
provides every flag, the `--check` rules, the `--log` logger, and the
output rules below.

A plugin is a standalone executable. Every input is a command-line flag;
every output is stdout, stderr, the exit code, or the files it's told to
write.

## Naming and discovery

A plugin for purl type `<kind>` (e.g. `oci`, `helm`, `npm`) is named
`bomify-plugin-<kind>` (`.exe` on Windows) and installed in
`<data-dir>/plugins` (`~/.bomify/plugins` by default), usually with
`bomify plugin install` (see
[plugins/README.md](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#installing-plugins)).
bomify never searches `PATH`.

`<kind>` is the component purl's type: `pkg:oci/nginx@1.27` needs
`bomify-plugin-oci`. The exception is `pkg:bomify-plugin/...`, a plugin
binary bomify handles itself (see
[publishing a plugin](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#publishing-a-plugin)).

## Commands

Every subcommand takes `--purl`, `--log`, and `--log-color` (see
[Logging](#logging)).

### `component pull`

```
bomify-plugin-<kind> component pull --purl <purl> --output <dir> --log <path> --log-color <bool>
```

Fetch or build the component `--purl` identifies into `--output`.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | The component's package URL. Everything the plugin needs to know comes from it. |
| `--output` | unless `--check` | Directory to write the artifact into. bomify creates it, empty, beforehand. Write a single file or a tree, whatever suits the artifact. Not passed with `--check=true`. |
| `--check` | no | See [Check mode](#check-mode). Default `false`. |

On success, print one [`Result`](#result) and exit `0`.

## Check mode

`--check=true` on `pull` asks the plugin to confirm a real pull would
succeed (the artifact exists and is readable) without transferring
content. `--output` isn't passed; don't require it.

Use the cheapest check available: a manifest HEAD, a resolve, a small
index fetch. A full pull is an acceptable last resort.

Print one `Result` on success, or exit non-zero with a one-line stderr
message. `hash` may be set if the check learns it for free (e.g. a
registry HEAD returning a digest).

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one `Result`, only on success. Nothing else, ever: bomify fails if stdout isn't that one JSON object. |
| stderr | One short fatal error message, only on failure. bomify appends it to its own error. |
| exit code | `0` on success; non-zero on failure. |

Everything else goes to the `--log` file.

## Result

Printed by `pull`. A missing key and a zero value are equivalent, so
`hash` may be absent, `{}`, or fully set.

```json
{
  "outputPath": "path/to/artifact",
  "message": "optional human-readable summary",
  "hash": { "algorithm": "SHA-256", "value": "9d5aec50e4ace532e44f5459f1f4d9c17180c96318103a6f64b765864967d31" }
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `outputPath` | string | yes | The path written (normally `--output`). With `--check`: whatever identifies what was checked (a resolved reference, a download URL). |
| `message` | string | no | Short human-readable summary. Logged, never parsed. |
| `hash` | object | no | The pulled artifact's SHA-256 (see [Hashes](#hashes)). Unset when it can't be computed. Never guess. |
| `hash.algorithm` | string | with `hash.value` | Always `SHA-256`. |
| `hash.value` | string | with `hash.algorithm` | Hex digest. Compared case-insensitively; lowercase by convention. |

Schema: [`result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/result.schema.json).

### Hashes

bomify checks every pulled component against the SHA-256 its SBOM
declares and keys its data directory by SHA-256, so that's the only
algorithm a plugin reports (`plugin.NewHash` builds one from a hex
digest). If a plugin can't compute it, it omits `hash` rather than
failing.

## Logging

- `--log <path>`: a file bomify creates empty right before the call.
  Append your log lines to it unconditionally. bomify streams it to its
  stdout under `--verbose` and deletes it when the plugin exits, so it's
  not a durable log.
- `--log-color <bool>`: whether ANSI colors are allowed in the log.
  bomify decides from its own stdout; don't detect it yourself.

`plugin.ComponentCommand` hands each call a ready-made `*slog.Logger` for
this (`plugin.OpenLog` opens one directly), in bomify's own log format.

## What bomify handles

Caching, concurrency, and state are bomify's job:

- Each invocation is fresh; nothing needs remembering between calls.
- bomify decides when a `pull` can be skipped and prevents concurrent
  pulls of the same purl.
- `--output` is always in the state described above.

Given the same flags, a plugin should do the same thing.
