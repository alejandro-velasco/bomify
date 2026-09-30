# Data directory

Everything lives under one directory (`~/.bomify`, or `--data-dir`).
Every path is derived in [`internal/layout`](https://github.com/alejandro-velasco/bomify/tree/main/internal/layout) and
nowhere else.

![Data directory layout](../diagrams/data-directory.svg)

*Source: [`docs/diagrams/data-directory.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/data-directory.mmd)*

- **`manifests/<hash>.json`** holds two kinds of record, told apart by
  hash space:
  - a build's manifest: the SBOM copied verbatim, keyed by its SHA-256
    ([`internal/build`](https://github.com/alejandro-velasco/bomify/tree/main/internal/build)). Tags point at these.
  - a component's pull manifest: its SBOM entry with the computed hash
    merged in, keyed by `layout.PurlHash`
    ([`internal/plugin`](https://github.com/alejandro-velasco/bomify/tree/main/internal/plugin)). This is what lets an
    identical component be reused across builds. `internal/oci/pull`
    writes one for every component it restores, too.
- **`layers/<purlHash>/`** is a component's pulled content.
- **`vulnerabilities/<purlHash>.json`** is a component's latest
  vulnerability report (see [Security scanning](security-scanning.md)),
  shared by every package containing that purl.
- **`package/repositories.json`** maps `repo -> tag -> sbom hash`.
- **`conf/*.json`** are the rule files: `distribution.json` (`bomify
  distribute` endpoints), `trust.json` (signature verification), and
  `scan.json` (scan policy). All three go through
  [`internal/rules`](https://github.com/alejandro-velasco/bomify/tree/main/internal/rules): a JSON array with one rule per
  identity, written atomically, resolved by the most specific
  `/`-segment prefix match ([`internal/prefix`](https://github.com/alejandro-velasco/bomify/tree/main/internal/prefix)).
- **`vex/` and `keys/`** are named, content-addressed stores
  ([`internal/namedstore`](https://github.com/alejandro-velasco/bomify/tree/main/internal/namedstore)): `<sha256><ext>`
  copies plus an `index.json` of names. Rules refer to entries by name,
  so they survive the original files moving. Re-adding a name is the
  only way to change its content, a copy is deleted once no name uses
  it, and a name can't be removed while a rule uses it.
  - `vex/` holds VEX documents that scan policy rules list.
  - `keys/` holds public keys and certificates that trust rules' key
    options name. Only public material is accepted: every PEM block must
    parse as a `CERTIFICATE`, PKIX `PUBLIC KEY`, or PKCS#1 `RSA PUBLIC
    KEY`, so a private key never lands here, even mislabeled.
    `--option key=<path>` still reads a file directly.
- **`plugins/`** holds installed `bomify-plugin-<kind>[.exe]` binaries,
  the only place bomify looks (`plugin.Find`; never `PATH`), plus
  `installed.json` recording where `bomify plugin install` got each.
- **`logs/<purlHash>.log`** is a plugin's log for one invocation. It is
  deleted when the plugin exits.

Every write that matters is atomic: a temp file or directory, renamed
into place once complete and verified (`fsutil.WriteFileAtomic`,
`fsutil.WriteJSON`, `internal/oci/pull`). A crash leaves a missing
file, never a corrupt one, and a missing file just means redo.
