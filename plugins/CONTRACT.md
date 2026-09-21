# bomify plugin contract

This is the authoritative specification for the subprocess contract between
`bomify` and a `bomify-plugin-<kind>` binary. It's aimed at anyone writing a
plugin, first- or third-party. The Go types referenced below
(`plugin.Result`, `plugin.Hash`, `plugin.RemoteResult`) live in
[`pkg/plugin`](../pkg/plugin) — a small library, importable from any Go
module, and `plugin.OpenLog`/`(*Result).Print`/`(*RemoteResult).Print` are
ready-made helpers a Go-based plugin can use instead of re-implementing
this spec by hand. See also [`README.md`](README.md) for the list of
first-party plugins and [`../ARCHITECTURE.md`](../ARCHITECTURE.md) for how
this contract fits into bomify's design as a whole.

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

A plugin must implement exactly three subcommands: `pull`, `push`, and
`remote`. All three take the flags below; italicized flags are shared by
all of them.

### `pull`

```
bomify-plugin-<kind> pull --purl <purl> --output <dir> --hash <algorithm> --log <path> --log-color <bool>
```

Fetches or builds the component `--purl` identifies and writes it into
`--output`.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | *The component's package URL. The plugin derives everything it needs to know about what to fetch from this string.* |
| `--output` | only when `--check` is false | Directory to write the pulled artifact into. bomify creates this directory before invoking the plugin — the plugin may assume it already exists and is empty, and should write directly into it (a single file, or a directory tree — whatever shape suits the artifact). Not passed at all when `--check=true`, since nothing is written. |
| `--hash` | no | Hash algorithm (see [Hash algorithms](#hash-algorithms) below) bomify wants the pulled artifact's content hash reported as, in the result's `hash` field. May be empty, in which case the plugin should omit `hash` from its result entirely. |
| `--check` | no | *See [Check mode](#check-mode). Defaults to `false`.* |
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
| `--input` | only when `--check` is false | Directory a prior `pull` (with the same `--purl`) wrote the artifact into. bomify guarantees this directory exists and holds exactly what that `pull` produced — never invoking `push` without a preceding successful `pull` for the same purl, unless `--check=true`, in which case `--input` isn't passed at all and no prior `pull` is required. |
| `--remote` | yes | Destination to publish to — the shape of this string is entirely kind-specific (a registry/repository prefix, a plain URL, etc.); document it in your plugin's own `--help`/README. |
| `--check` | no | *See [Check mode](#check-mode). Defaults to `false`.* |
| `--log` | yes | *See [Logging](#logging).* |
| `--log-color` | yes | *See [Logging](#logging).* |

On success, the plugin must print a single `Result` JSON object to stdout
and exit `0`. `hash` is meaningless for a push result and should be left
unset.

### `remote`

```
bomify-plugin-<kind> remote --purl <purl> --log <path> --log-color <bool>
```

Reports where the component `--purl` identifies comes from or is
published under — its registry, repository, or source location — without
fetching or publishing anything. bomify uses this to match `--purl`
against a `bomify distribute` rule scoped by origin (`bomify distribution
create`'s `--match`), not just by plugin kind, and — when that rule's
`--match` is non-empty — as the basis for a mirror substitution: the
part of `remote` past the matched prefix is preserved and handed back to
`push` as part of `--remote`, so a matched rule redirects a component
without collapsing everything under it onto one shared destination. See
[RemoteResult](#remoteresult) for exactly what shape `remote` must
report for that substitution to come out right.

| Flag | Required | Meaning |
| --- | --- | --- |
| `--purl` | yes | *The component's package URL. The plugin derives its answer entirely from this string — `remote` never touches the network, a registry, or any local files.* |
| `--log` | yes | *See [Logging](#logging).* |
| `--log-color` | yes | *See [Logging](#logging).* |

On success, the plugin must print a single `RemoteResult` JSON object (see
[RemoteResult](#remoteresult)) to stdout and exit `0`.

`remote` must be a pure function of `--purl`: unlike `pull`/`push`, it
never touches the data directory, is never skipped or cached by bomify,
and may be invoked far more often per purl than `pull`/`push` ever are.

## Check mode

Passing `--check=true` to `pull` or `push` asks the plugin to verify
that a real `pull`/`push` would succeed — the artifact exists and the
caller is authorized to fetch it (`pull`), or the destination is
reachable and the caller is authorized to write to it (`push`) —
without actually transferring the artifact's content. `--output`
(`pull`) / `--input` (`push`) are not passed at all in this mode, since
nothing is written or read; a plugin must not require them when
`--check=true`.

A plugin should exhaust every inexpensive option before falling back to
anything approximating the real operation:

- Prefer a manifest/metadata HEAD or resolve, a small index/listing
  fetch, or similar — something whose cost doesn't scale with the
  artifact's size.
- For `pull --check`, actually performing a full `pull` is an acceptable
  (if undesirable) last resort when no cheaper verification exists.
- For `push --check`, a real, mutating write is **never** acceptable as
  a fallback — unlike a redundant `pull`, a redundant `push` can have
  real side effects (consuming a single-use destination like a
  presigned upload URL, or overwriting something the caller didn't
  intend to touch yet). If nothing cheaper is available, report
  whatever partial verification was possible (e.g. reachability, but
  not authorization) rather than actually writing — see
  `bomify-plugin-generic`'s `push --check` for exactly this tradeoff.

On success, print a single `Result` JSON object (the same shape as a
normal `pull`/`push`) to stdout and exit `0`; on failure, exit non-zero
with the usual one-line stderr message. `hash` may still be populated if
the check happens to learn it for free (e.g. a registry HEAD returning a
digest) — same optional, best-effort rules as a normal `pull`. See
[Result](#result) for how `outputPath`'s meaning broadens in this mode.

## Standard streams

| Stream | Reserved for |
| --- | --- |
| stdout | Exactly one `Result` or `RemoteResult` JSON object (depending on the subcommand), printed only on success. Nothing else may ever be written here — no progress output, no debug prints, nothing. bomify parses stdout as JSON and fails the whole operation if it isn't exactly that. |
| stderr | A single, short, human-readable fatal error message, written only on failure (non-zero exit). bomify captures this and appends it verbatim to the error it reports. Like stdout, this is not a place for routine logging. |
| exit code | `0` on success (with valid JSON on stdout). Any non-zero value on failure. |

A plugin's own routine/diagnostic logging — anything you'd otherwise be
tempted to write to stdout or stderr — must go to the file named by
`--log` instead. See [Logging](#logging).

## Result

The single JSON object a plugin prints to stdout on success. bomify parses
this straight into a Go struct, where a missing key and a key present with
its zero value are indistinguishable — so `hash` may be omitted entirely,
or present as `{}` or with both fields set; all three are equally valid
and bomify treats them identically:

```json
{
  "outputPath": "path/to/artifact/or/remote/reference",
  "message": "optional human-readable summary",
  "hash": { "algorithm": "SHA-256", "value": "9d5aec50e4ace532e44f5459f1f4d9c17180c96318103a6f64b765864967d31" }
}
```

```json
{ "outputPath": "path/to/artifact/or/remote/reference" }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `outputPath` | string | yes | For `pull`: the local path the artifact was written to (normally just `--output`, echoed back). For `push`: the reference the artifact was published under at `--remote` (e.g. `<remote>/<name>:<version>`). For either subcommand with `--check=true`: no path was written to or read from, so report whatever identifies the artifact/destination that was checked instead (e.g. the resolved registry reference or download URL). |
| `message` | string | no | A short, human-readable summary of what happened (e.g. `"pulled nginx:1.27"`). Purely informational — bomify logs it but never parses it. |
| `hash` | object | no | The content hash of the pulled artifact, for the algorithm `--hash` requested. Only meaningful for `pull`; leave both of its fields unset for `push`, and for `pull` when either `--hash` was empty or the algorithm requested isn't one the plugin can compute — never report a hash for a different algorithm than what was requested, and never guess. |
| `hash.algorithm` | string | present only together with `hash.value` | One of the [CycloneDX hash algorithm names](#hash-algorithms) below — must exactly equal the `--hash` value the plugin was given. |
| `hash.value` | string | present only together with `hash.algorithm` | The digest itself, hex-encoded. Case doesn't matter (bomify compares case-insensitively), but lowercase is the convention every first-party plugin follows. |

Go plugins should build this as a `plugin.Result` (see
[`pkg/plugin`](../pkg/plugin)) and print it with `(*Result).Print`,
rather than hand-rolling the JSON encoding.

A machine-readable version of this schema, suitable for validating a
plugin's actual stdout output with any off-the-shelf JSON Schema
validator, is published at
[`result.schema.json`](result.schema.json).

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

## RemoteResult

The single JSON object a plugin's `remote` subcommand prints to stdout on
success:

```json
{ "remote": "docker.io/library" }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `remote` | string | yes | Where this component comes from or is published under, in whatever shape is meaningful for this plugin's kind (a registry/namespace address, a source URL, etc.). |

`remote` must be reported in **the same shape your plugin's own `push`
expects `--remote` to arrive in** — because a matched `bomify distribute`
rule can hand `push` back a `--remote` built directly from what `remote`
reported (see `remote`'s [Commands](#commands) entry above for the mirror
substitution this enables). Concretely:

- If `push` appends the component's own name/tag onto `--remote` itself
  (as every first-party plugin's OCI/Helm-style `push` does), `remote`
  must **not** include that trailing name — report only the
  registry/namespace it lives under (e.g. `docker.io/library`, not
  `docker.io/library/nginx`), exactly as `bomify-plugin-oci` does.
- If `push` instead treats `--remote` as the exact, complete destination
  with nothing appended (as `bomify-plugin-generic`'s does, since a
  presigned upload URL can't tolerate anything appended to it), `remote`
  should be that same complete address, unabridged.

The only thing bomify relies on structurally, either way, is that two
components sharing a common origin (e.g. the same registry namespace)
report a `remote` sharing a common `/`-separated prefix, since that's
what a `bomify distribute` rule's `--match` compares against, and what
gets substituted out of it on a match.

Go plugins should build this as a `plugin.RemoteResult` (see
[`pkg/plugin`](../pkg/plugin)) and print it with `(*RemoteResult).Print`,
rather than hand-rolling the JSON encoding.

A machine-readable version of this schema is published at
[`remote-result.schema.json`](remote-result.schema.json).

## Logging

A plugin must never write its own routine logging to stdout (reserved for
the `Result`/`RemoteResult` JSON) or stderr (reserved for a single fatal
message on failure). Instead:

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
[`pkg/plugin`](../pkg/plugin)) to get a ready-made
`*slog.Logger` for this, in the same format bomify's own CLI logging uses,
rather than constructing one by hand.

## What a plugin does *not* need to handle

All caching, concurrency control, and state tracking across invocations is
bomify's responsibility, not the plugin's:

- A plugin is invoked fresh for every `pull`/`push`/`remote`; it never
  needs to remember anything between invocations.
- bomify — not the plugin — decides when a `pull` can be skipped because
  an equivalent one already succeeded, and guards against two concurrent
  `pull`s for the same purl racing each other.
- `--output`/`--input` directories are always exactly what this contract
  describes above; a plugin never needs to defend against a partially
  written or unexpected directory state.

A plugin should be a pure function of its flags: given the same `--purl`
(and, for `push`, the same `--input`), do the same thing, and leave
anything more stateful than that to bomify. `remote` is the purest of the
three — given the same `--purl`, it must always report the same `remote`,
independent of anything on disk, the network, or a prior `pull`/`push`.
