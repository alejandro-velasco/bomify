---
icon: lucide/puzzle
---

# Building a plugin

This walks through writing a **component plugin**, which fetches and
publishes one purl type for `bomify build` and `bomify distribute`. The
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

It implements three subcommands:

- **`component pull`** fetches the component `--purl` names into
  `--output`, reporting its SHA-256 if it can.
- **`component push`** publishes what `pull` wrote into `--input` to
  `--remote`.
- **`component remote`** reports where the component lives, so `bomify
  distribute` can match it against rules.

`pull` and `push` also have a `--check` mode. stdout carries exactly one
JSON result, stderr one fatal message on failure, and logging goes to
the `--log` file.

## In Go

Implement [`pkg/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/pkg/plugin)'s
`ComponentPlugin` interface (`Pull`, `Push`, `Remote`, each given the
parsed flags and a logger writing to `--log`). `plugin.ComponentCommand`
builds the subcommands, and `plugin.Run` runs them with the contract's
exit and stderr rules.

[`bomify-plugin-generic`](https://github.com/alejandro-velasco/bomify/tree/main/plugins/bomify-plugin-generic)
(an HTTP GET on pull, a PUT on push) is the simplest template:

```
bomify-plugin-generic/
├─ main.go              # plugin.Run(cmd.NewRootCmd())
├─ cmd/root.go          # a ComponentPlugin over internal/artifact
└─ internal/artifact/   # purl resolution and the GET/PUT/HEAD logic, no CLI code
```

Keeping `cmd/` a thin adapter and the logic in `internal/` makes the
logic easy to test.

## Checklist

- [ ] Implement all three subcommands exactly per the
      [contract](component-contract.md).
- [ ] Print nothing on stdout but the one JSON result, and log only to
      `--log`.
- [ ] Support `--check` if there's a cheap check, and never fall back to
      a real push for it (see [check mode](component-contract.md#check-mode)).
- [ ] Validate your output against
      [`result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/result.schema.json)
      and [`remote-result.schema.json`](https://github.com/alejandro-velasco/bomify/blob/main/plugins/contracts/component/v1/remote-result.schema.json).
- [ ] To make it installable, publish it as a
      [plugin package](../getting-started/installing-plugins.md#publishing-a-plugin).
- [ ] For a first-party plugin, add it to
      [`plugins/README.md`](../getting-started/installing-plugins.md).
