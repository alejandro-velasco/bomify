---
icon: lucide/puzzle
---

# Building a plugin

This walks through writing a **component plugin**, which fetches one
purl type for `bomify build`. The
[component contract](component-contract.md) is the spec; if this page
disagrees with it, the contract wins. The other contracts are shorter
and independent: [SBOM generation](sbom-contract.md),
[security scanning](security-contract.md), and
[signing](signing-contract.md).

## What a plugin is

A standalone executable, in any language, named `bomify-plugin-<kind>`
and installed in `~/.bomify/plugins`. `<kind>` is the purl type it
handles: `pkg:oci/nginx@1.27` needs `bomify-plugin-oci`. Inputs are
flags; outputs are stdout, stderr, the exit code, and the files it
writes.

It implements two subcommands:

- **`component pull`** fetches the component `--purl` names into
  `--output`, reporting its SHA-256 if it can. It also has a `--check`
  mode.
- **`component pack`** describes what `pull` wrote as an OCI artifact in
  its kind's registry format, such as an image or a Helm chart, for
  `bomify push` to put in the package's index as it is. A kind with no
  format of its own prints `{}`.

stdout carries exactly one JSON result, stderr one fatal message on
failure, progress goes to the `--progress` file, and logging to the
`--log` file.

## In Go

Implement [`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)'s
`ComponentPlugin` interface (`Pull`, given the parsed flags, a logger
writing to `--log`, and a `Progress` writing to `--progress`), and `ComponentPacker` (`Pack`) if the kind has a
registry format. `plugin.ComponentCommand` builds the subcommands,
answering `pack` with `{}` for a plugin that doesn't pack, and
`plugin.Run` runs them with the contract's exit and stderr rules.

[`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic)
(an HTTP GET) is the simplest template:

```
bomify-plugin-generic/
├─ main.go              # plugin.Run(cmd.NewRootCmd())
├─ cmd/root.go          # a ComponentPlugin over internal/artifact
└─ internal/artifact/   # purl resolution and the GET/HEAD logic, no CLI code
```

Keeping `cmd/` a thin adapter and the logic in `internal/` makes the
logic easy to test.

It has no registry format, so it doesn't pack. For `pack`, see
[`bomify-plugin-oci`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-oci)'s,
which describes the image it pulled as it is, and
[`bomify-plugin-helm`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-helm)'s,
which builds a chart's config and manifest beside the archive it pulled.

## Checklist

- [ ] Implement `pull` and `pack` exactly per the
      [contract](component-contract.md).
- [ ] Print nothing on stdout but the one JSON result, and log only to
      `--log`.
- [ ] Support `--check` with the cheapest check there is (see
      [check mode](component-contract.md#check-mode)).
- [ ] Report each download's [progress](component-contract.md#progress),
      or bomify shows only that the pull is running.
- [ ] Make `pack` reproducible: the same `--input` gives the same
      artifact, byte for byte, with no timestamp in it.
- [ ] Validate your output against
      [`result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/result.schema.json)
      and [`pack-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/pack-result.schema.json),
      and your progress lines against
      [`progress.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/progress.schema.json).
- [ ] To make it installable, publish it as a
      [plugin package](../getting-started/installing-plugins.md#publishing-a-plugin).
- [ ] For a first-party plugin, add it to
      [`plugins/README.md`](../getting-started/installing-plugins.md).
