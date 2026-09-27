---
icon: lucide/puzzle
---

# Building a plugin

bomify doesn't know how to fetch or publish anything itself — every purl
type is handled by an external `bomify-plugin-<kind>` binary's **component
plugin** subcommands. This page is a guided walkthrough for writing one;
it isn't the spec. The
[**component plugin contract**](component-contract.md)
is the authoritative, normative reference for every flag, JSON shape, and
edge case — read it before you start, and treat anything here that seems to
disagree with it as this page being out of date, not the other way around.

A `bomify-plugin-<kind>` binary can separately implement either or both
of two other, entirely independent contracts — this page's walkthrough
is specific to component plugins, so see the contract itself directly if
you're building one of these instead:

- **[SBOM generation plugin contract](sbom-contract.md)** (`sbom
  generate`) — a much lighter, standalone-runnable contract for building
  a fresh SBOM from a deployment medium; bomify contributes nothing
  beyond locating the binary.
- **[Security scanning plugin contract](security-contract.md)**
  (`security scan --purl <purl>`) — a similarly lightweight per-call
  contract (a plugin just answers "what does this purl have"), but
  bomify itself owns loading the SBOM, dispatching one call per
  component, and merging the results — closer to the component contract
  in that respect.

## What a plugin actually is

A `bomify-plugin-<kind>` is a standalone executable. It doesn't link against
bomify or share memory with it — every input arrives as a command-line
flag, and every output is stdout, stderr, an exit code, or the files it's
told to write to. This means a plugin can be written in any language; bomify
only cares that the binary is named `bomify-plugin-<kind>` and is
discoverable on `PATH`.

`<kind>` comes directly from the purl type of the components it should
handle — a component with purl `pkg:oci/nginx@1.27` needs a
`bomify-plugin-oci` on `PATH`.

## The subcommands, briefly

A component plugin implements three subcommands, nested under `component`
— `component pull`, `component push`, and `component remote` — plus an
optional `--check` mode on `pull`/`push` for verifying an operation would
succeed without actually doing it. Each has its own required/optional flags
and JSON result shape, all specified in
[`COMPONENT-CONTRACT.md`](component-contract.md#commands):

- **`component pull`** fetches the component `--purl` identifies into
  `--output`, and reports a content hash for `--hash` if it can compute
  one.
- **`component push`** publishes whatever a prior `pull` wrote into
  `--input` to `--remote`.
- **`component remote`** reports where a component's content currently
  lives — independent of any specific `--remote` — so `bomify distribute`
  can match it against a mirroring rule.

Routine logging goes to the file named by `--log`, never to stdout (reserved
for exactly one JSON result on success) or stderr (reserved for one fatal
message on failure).

## Using the Go helper library

If you're writing a plugin in Go, [`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)
is a small, importable library implementing the contract's Go-facing side —
`Result`/`Hash`/`RemoteResult` structs with `Print` methods that encode them
correctly, and `OpenLog` for the `--log` file. Use it instead of
hand-rolling JSON encoding or log setup; nothing about it depends on being
inside bomify's own module.

## Worked example: `bomify-plugin-generic`

[`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic)
is the simplest first-party plugin — a plain HTTP GET on pull, a PUT on
push — and a reasonable template to start from. Its shape:

```
bomify-plugin-generic/
├─ main.go              # entrypoint, calls cmd.Execute()
├─ cmd/
│  ├─ root.go            # wires up the "component" subcommand
│  ├─ pull.go             # the `component pull` subcommand's flags + RunE
│  ├─ push.go             # the `component push` subcommand's flags + RunE
│  └─ remote.go           # the `component remote` subcommand's flags + RunE
└─ internal/artifact/
   ├─ resolve.go          # purl -> Ref (the download URL, name, version)
   └─ transfer.go         # the actual GET/PUT/HEAD logic
```

The pattern worth copying: `cmd/*.go` is thin — cobra flag parsing, opening
the log via `plugin.OpenLog`, calling into `internal/<pkg>`, printing the
result — and all the real logic (resolving the purl, doing the network
call, building the `plugin.Result`) lives in an internal package with no
cobra/CLI dependency at all. That split is what makes each piece
independently testable; see `internal/artifact/*_test.go` for the tests
that result from it.

`remote.go` is a good one to read first — it's the smallest subcommand, and
shows the full round-trip: parse `--purl`, open the log, do the (here,
trivial) work, print a `plugin.RemoteResult`.

## Checklist

- [ ] Implement `component pull`, `component push`, and `component remote`
      exactly per
      [`COMPONENT-CONTRACT.md`](component-contract.md) —
      required/optional flags, the `Result`/`RemoteResult` JSON shapes, exit
      codes.
- [ ] Nothing but the one JSON result on stdout, ever — no progress output,
      no debug prints.
- [ ] Route all routine logging through `--log`.
- [ ] Support `--check` on `pull`/`push` if there's a genuinely inexpensive
      way to verify the operation would succeed (see `COMPONENT-CONTRACT.md`'s
      [check mode](component-contract.md#check-mode)
      section) — and never fall back to the real, mutating operation just
      to implement it.
- [ ] Validate your plugin's actual JSON output against
      [`result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/result.schema.json)/[`remote-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/remote-result.schema.json)
      with any off-the-shelf JSON Schema validator.
- [ ] Name the binary `bomify-plugin-<kind>` and put it on `PATH` — that's
      all bomify needs to find it.

If you're building a plugin bomify ships itself rather than a third-party
one, also add it to the table in
[`plugins/README.md`](../getting-started/installing-plugins.md).
