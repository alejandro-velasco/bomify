# bomify plugin contract

This is the authoritative specification for the subprocess contract between
`bomify` and a `bomify-plugin-<kind>` binary. It's aimed at anyone writing a
plugin, first- or third-party. The Go types referenced below
(`plugin.Result`, `plugin.Hash`) live in [`internal/plugin`](../internal/plugin)
— that package is bomify's own (caller-side) implementation of this same
contract, and `plugin.OpenLog`/`(*Result).Print` are ready-made helpers a
Go-based plugin can use instead of re-implementing this spec by hand. See
also [`README.md`](README.md) for the list of first-party plugins and
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) for how this contract fits into
bomify's design as a whole.

A plugin is a standalone executable. It does not link against bomify, share
memory with it, or receive anything over stdin — every input arrives as a
command-line flag, and every output is either the process's stdout, stderr,
exit code, or the files it's told to write to.

## Naming and discovery

A plugin for purl type `<kind>` (e.g. `oci`, `helm`, `npm`) must be:

- named exactly `bomify-plugin-<kind>` (`bomify-plugin-<kind>.exe` on
  Windows, handled automatically by Go's `exec.LookPath`)
- discoverable on `PATH`

bomify determines `<kind>` directly from the SBOM component's purl type
(e.g. a component with purl `pkg:oci/nginx@1.27` needs `bomify-plugin-oci`
on `PATH`) and never invokes a plugin by any other name or location.

## Commands

A plugin must implement exactly two subcommands, `pull` and `push`. Both
take the flags below; italicized flags are shared by both subcommands.

### `pull`

```
bomify-plugin-<kind> pull --purl <purl> --output <dir> --hash <algorithm> --log <path> --log-color <bool>
```

Fetches or builds the component `--purl` identifies and writes it into
`--output`.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | *The component's package URL. The plugin derives everything it needs to know about what to fetch from this string.* |
| `--output` | yes | Directory to write the pulled artifact into. bomify creates this directory before invoking the plugin — the plugin may assume it already exists and is empty, and should write directly into it (a single file, or a directory tree — whatever shape suits the artifact). |
| `--hash` | no | Hash algorithm (see [Hash algorithms](#hash-algorithms) below) bomify wants the pulled artifact's content hash reported as, in the result's `hash` field. May be empty, in which case the plugin should omit `hash` from its result entirely. |
| `--log` | yes | *See [Logging](#logging).* |
| `--log-color` | yes | *See [Logging](#logging).* |

On success, the plugin must print a single `Result` JSON object (see
[Result](#result)) to stdout and exit `0`.

### `push`

```
bomify-plugin-<kind> push --purl <purl> --input <dir> --remote <endpoint> --log <path> --log-color <bool>
```

Publishes the artifact a prior `pull` wrote into `--input` to `--remote`.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | *Same purl as the `pull` that produced `--input`'s contents.* |
| `--input` | yes | Directory a prior `pull` (with the same `--purl`) wrote the artifact into. bomify guarantees this directory exists and holds exactly what that `pull` produced — never invoking `push` without a preceding successful `pull` for the same purl. |
| `--remote` | yes | Destination to publish to — the shape of this string is entirely kind-specific (a registry/repository prefix, a plain URL, etc.); document it in your plugin's own `--help`/README. |
| `--log` | yes | *See [Logging](#logging).* |
| `--log-color` | yes | *See [Logging](#logging).* |

On success, the plugin must print a single `Result` JSON object to stdout
and exit `0`. `hash` is meaningless for a push result and should be left
unset.

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one `Result` JSON object, printed only on success. Nothing else may ever be written here — no progress output, no debug prints, nothing. bomify parses stdout as JSON and fails the whole operation if it isn't exactly that. |
| stderr | A single, short, human-readable fatal error message, written only on failure (non-zero exit). bomify captures this and appends it verbatim to the error it reports. Like stdout, this is not a place for routine logging. |
| exit code | `0` on success (with a valid `Result` on stdout). Any non-zero value on failure. |

A plugin's own routine/diagnostic logging — anything you'd otherwise be
tempted to write to stdout or stderr — must go to the file named by
`--log` instead. See [Logging](#logging).

## Result

The single JSON object a plugin prints to stdout on success:

```json
{
  "outputPath": "path/to/artifact/or/remote/reference",
  "message": "optional human-readable summary",
  "hash": { "algorithm": "SHA-256", "value": "9d5aec50e4ace532e44f5459f1f4d9c17180c96318103a6f64b765864967d31" }
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `outputPath` | string | yes | For `pull`: the local path the artifact was written to (normally just `--output`, echoed back). For `push`: the reference the artifact was published under at `--remote` (e.g. `<remote>/<name>:<version>`). |
| `message` | string | no | A short, human-readable summary of what happened (e.g. `"pulled nginx:1.27"`). Purely informational — bomify logs it but never parses it. |
| `hash` | object | no | The content hash of the pulled artifact, for the algorithm `--hash` requested. Only meaningful for `pull`; omit entirely for `push`, and for `pull` when either `--hash` was empty or the algorithm requested isn't one the plugin can compute — never report a hash for a different algorithm than what was requested, and never guess. |
| `hash.algorithm` | string | yes, if `hash` is present | One of the [CycloneDX hash algorithm names](#hash-algorithms) below — must exactly equal the `--hash` value the plugin was given. |
| `hash.value` | string | yes, if `hash` is present | The digest itself, hex-encoded. Case doesn't matter (bomify compares case-insensitively), but lowercase is the convention every first-party plugin follows. |

Go plugins should build this as a `plugin.Result` (see
[`internal/plugin`](../internal/plugin)) and print it with `(*Result).Print`,
rather than hand-rolling the JSON encoding.

### Hash algorithms

`--hash`'s value, and `hash.algorithm` in the result, must be one of the
canonical [CycloneDX](https://cyclonedx.org/) hash algorithm names:

`MD5`, `SHA-1`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`, `SHA3-384`,
`SHA3-512`, `BLAKE2b-256`, `BLAKE2b-384`, `BLAKE2b-512`, `BLAKE3`,
`Streebog-256`, `Streebog-512`.

bomify normalizes case- and hyphen-insensitive input (e.g. a user-supplied
`--hash sha256`) to one of these exact strings (see
`plugin.NormalizeHashAlgorithm`) before ever invoking a plugin, so a plugin
only ever needs to compare `--hash` against this exact list — never
normalize it itself. A plugin unable to compute the requested algorithm
should not error because of that alone; it should simply omit `hash` from
its result.

## Logging

A plugin must never write its own routine logging to stdout (reserved for
the `Result` JSON) or stderr (reserved for a single fatal message on
failure). Instead:

- `--log <path>` names a file, created empty by bomify immediately before
  the plugin starts, that the plugin should open (for appending) and write
  its own leveled/diagnostic log lines to. bomify streams this file live
  to its own stdout while the plugin runs, but only when running with
  `--verbose` — so a plugin should write to it unconditionally and let
  bomify decide whether anything downstream actually sees it.
- This file is **not persistent**: bomify deletes it again once the
  plugin exits, regardless of outcome. It exists solely to make live
  streaming possible, not as a durable log a plugin can rely on
  surviving.
- `--log-color <bool>` (`true`/`false`) tells the plugin whether it's safe
  to include ANSI color escape codes in the lines it writes to `--log`.
  bomify sets this based on whether *its own* stdout is a real terminal —
  a plugin should never make that determination itself, since it has no
  visibility into what bomify's stdout is ultimately connected to.

Go plugins should call `plugin.OpenLog(logPath, logColor)` (see
[`internal/plugin`](../internal/plugin)) to get a ready-made
`*slog.Logger` for this, in the same format bomify's own CLI logging uses,
rather than constructing one by hand.

## What a plugin does *not* need to handle

All caching, concurrency control, and state tracking across invocations is
bomify's responsibility, not the plugin's:

- A plugin is invoked fresh for every `pull`/`push`; it never needs to
  remember anything between invocations.
- bomify — not the plugin — decides when a `pull` can be skipped because
  an equivalent one already succeeded, and guards against two concurrent
  `pull`s for the same purl racing each other.
- `--output`/`--input` directories are always exactly what this contract
  describes above; a plugin never needs to defend against a partially
  written or unexpected directory state.

A plugin should be a pure function of its flags: given the same `--purl`
(and, for `push`, the same `--input`), do the same thing, and leave
anything more stateful than that to bomify.
