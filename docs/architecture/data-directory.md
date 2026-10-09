# Data directory

Everything lives under one directory (`~/.bomify`, or `--data-dir`).
Every path is derived in [`internal/layout`](https://github.com/alejandro-velasco/bomify/tree/main/internal/layout) and
nowhere else.

![Data directory layout](../diagrams/data-directory.svg)

*Source: [`docs/diagrams/data-directory.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/data-directory.mmd)*

- **`version.json`** is the directory's version (see
  [Versioning](#versioning)).
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
- **`vulnerabilities/<purlHash>/<scanner>.json`** is each scanner's
  latest vulnerability report of a component (see
  [Security scanning](security-scanning.md)), shared by every package
  containing that purl.
- **`provenance/<sbomHash>.json`** is a build's SLSA provenance, if it
  was built with `--provenance` (see [Build provenance](provenance.md)).
- **`package/repositories.json`** maps `repo -> tag -> sbom hash`.
- **`conf/*.json`** are the rule files: `distribution.json` (`bomify
  distribute` endpoints), `trust.json` (signature verification), and
  `scan.json` (scan policy). All three go through
  [`internal/rules`](https://github.com/alejandro-velasco/bomify/tree/main/internal/rules): a JSON array with one rule per
  identity, written atomically, resolved by the most specific
  `/`-segment prefix match ([`internal/prefix`](https://github.com/alejandro-velasco/bomify/tree/main/internal/prefix)).
- **`conf/signers.json`** is the named signers `push`/`save --sign`
  use (`bomify signer create`): each a signing plugin and its options,
  such as a private key's path, never key material. It's stored with
  `internal/rules` too, one entry per name, but never matched against a
  reference.
- **`conf/auth.json`** is registry credentials, in Docker's
  `config.json` format (see [Credentials](registry.md#credentials)).
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

## Versioning

`version.json` records which version of this layout the directory is
in. Every command that uses the directory checks it first
([`layout.CheckVersion`](https://github.com/alejandro-velasco/bomify/blob/main/internal/layout/version.go));
`version`, `help`, `completion`, and docs generation skip the check.

| Directory | bomify |
| --- | --- |
| Missing or empty | Records the current version. |
| Current version | Uses it. |
| Older version | Migrates it in place, one version at a time, recording each step as it completes, so a crash resumes where it stopped. |
| Newer version | Refuses, naming both versions. |
| Content but no version | Refuses: a pre-alpha bomify wrote it, and pre-alpha data doesn't carry over. |

Build tooling that puts files into a data directory before bomify has
run starts it with `version.json` first, through `init_data_dir` in
[`hack/common.sh`](https://github.com/alejandro-velasco/bomify/blob/main/hack/common.sh):
`make install-plugins` (and so a container image built from a checkout)
and `hack/push-plugin-packages.sh`.

The version covers the layout above and the schemas of the files bomify
reads back: the `conf/` rule files and `signers.json`,
`repositories.json`, the `keys/` and `vex/` indexes, `installed.json`,
and the manifest and provenance records. Changing any of them in a way an
older bomify would misread bumps `layout.CurrentVersion` and adds a
migration in the same change. Adding an optional field doesn't. The
`conf/` rule files are read strictly, so an older bomify refuses a
field it doesn't know rather than verifying or gating less than the
rule says; their fields are in [Signing](signing.md#rule-files) and
[Security scanning](security-scanning.md#policy-rules). `auth.json`
isn't covered: it's Docker's format, not bomify's.
