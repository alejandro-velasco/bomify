# Architecture

How bomify works internally: the data directory, the plugin contracts,
build bookkeeping, and moving packages through a registry or tarball.
For using the CLI, see the [README](README.md) and
[`docs/reference`](docs/reference).

Diagrams are rendered from the Mermaid sources in
[`docs/diagrams`](docs/diagrams); after editing a `.mmd`, run `make
diagrams`.

## Mental model

bomify mirrors Docker: a **package** is built from a CycloneDX SBOM the
way an image is built from a Dockerfile, a **tag** names one, and
`packages`/`tag`/`package rm`/`save`/`load` map onto
`images`/`tag`/`rmi`/`save`/`load`. Docker's layers are bomify's
**components**, each pulled, cached, and reused independently by
content hash.

bomify only orchestrates. Fetching, publishing, scanning, and signing
are done by external `bomify-plugin-<kind>` binaries.

## Data directory

Everything lives under one directory (`~/.bomify`, or `--data-dir`).
Every path is derived in [`internal/layout`](internal/layout) and
nowhere else.

![Data directory layout](docs/diagrams/data-directory.svg)

*Source: [`docs/diagrams/data-directory.mmd`](docs/diagrams/data-directory.mmd)*

- **`manifests/<hash>.json`** holds two kinds of record, told apart by
  hash space:
  - a build's manifest: the SBOM copied verbatim, keyed by its SHA-256
    ([`internal/build`](internal/build)). Tags point at these.
  - a component's pull manifest: its SBOM entry with the computed hash
    merged in, keyed by `layout.PurlHash`
    ([`internal/plugin`](internal/plugin)). This is what lets an
    identical component be reused across builds. `internal/oci/pull`
    writes one for every component it restores, too.
- **`layers/<purlHash>/`** is a component's pulled content.
- **`vulnerabilities/<purlHash>.json`** is a component's latest
  vulnerability report (see [Security scanning](#security-scanning)),
  shared by every package containing that purl.
- **`package/repositories.json`** maps `repo -> tag -> sbom hash`.
- **`conf/*.json`** are the rule files: `distribution.json` (`bomify
  distribute` endpoints), `trust.json` (signature verification), and
  `scan.json` (scan policy). All three go through
  [`internal/rules`](internal/rules): a JSON array with one rule per
  identity, written atomically, resolved by the most specific
  `/`-segment prefix match ([`internal/prefix`](internal/prefix)).
- **`vex/` and `keys/`** are named, content-addressed stores
  ([`internal/namedstore`](internal/namedstore)): `<sha256><ext>`
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

## Plugin architecture

A plugin binary can implement any of four independent contracts:

| Contract | Subcommands | Used by | `<kind>` names |
| --- | --- | --- | --- |
| [Component](plugins/COMPONENT-CONTRACT.md) | `component pull/push/remote` | `build`, `distribute` | a purl type |
| [SBOM generation](plugins/SBOM-CONTRACT.md) | `sbom generate` | `sbom generate` | a deployment medium |
| [Security scanning](plugins/SECURITY-CONTRACT.md) | `security scan/supported-components` | `security scan`, scan on pull | a scanner |
| [Signing](plugins/SIGNING-CONTRACT.md) | `signature sign/verify/supported-types` | `--sign`, `--verify` | a signing scheme |

Every call bomify makes to a plugin goes through `plugin.Invoke`: run
the binary, parse stdout as the contract's JSON result, and fold stderr
into the error on failure. On the plugin side, `pkg/plugin`'s
`ComponentCommand`, `SecurityCommand`, and `SignatureCommand` build each
contract's subcommands (flags, validation, logging, output) around a
small Go interface, so a first-party plugin's `cmd` package is only an
adapter over its `internal` logic.

### Component plugins

For each SBOM component, `bomify build` and `bomify distribute`:

1. **Detect** the kind from the purl type (`plugin.Detect`):
   `pkg:oci/...` is `oci`. A missing or unparseable purl fails.
2. **Find** `bomify-plugin-<kind>` in `plugins/`. The exception is
   `pkg:bomify-plugin/...`: a plugin binary itself, which `build` copies
   directly (see [Plugin installation](#plugin-installation)) and
   `distribute` skips.
3. **Delegate**: `component pull --purl --output` or `component push
   --purl --input --remote`. The plugin prints one JSON `{outputPath,
   message, hash}`, where `hash` is the SHA-256 of what it pulled.
   `distribute` first calls `component remote` to learn the component's
   origin, then picks the destination: `--remote <kind>=<endpoint>`,
   else the best `conf/distribution.json` rule matching that origin
   ([`internal/distribution`](internal/distribution)).

stdout is reserved for the result and stderr for one fatal message.
Plugins log to `--log`, `logs/<purlHash>.log`, which bomify creates
fresh before each call, streams to its own stdout under `--verbose`
(prefixed `[<verb> <purl>]`), and deletes afterwards. `--log-color`
passes on whether bomify's stdout is a terminal.

`--check` on `build`/`distribute` passes `--check=true` instead of
`--output`/`--input`, asking the plugin to cheaply confirm the transfer
would succeed. `plugin.CheckPull`/`CheckPush` are stateless: no pid
file, manifest, or layer directory, and `build --check` records no build.

![Plugin dispatch sequence](docs/diagrams/plugin-dispatch.svg)

*Source: [`docs/diagrams/plugin-dispatch.mmd`](docs/diagrams/plugin-dispatch.mmd)*

### SBOM generation

`bomify sbom generate <kind> [flags]` finds `bomify-plugin-<kind>`, runs
its `sbom generate` with the flags unparsed, wires stdin/stdout/stderr
straight through, and propagates the exit code. That's all: no JSON
result, log file, or caching, so the plugin works exactly the same run
directly.

### Security scanning

`bomify security scan <type> <tag>` (`cmd/security.go`):

1. Resolves `<tag>` (`build.ResolveTag`) and walks its SBOM.
2. Finds `bomify-plugin-<type>`. One scanner handles every component,
   whatever its purl type.
3. Asks it once for `security supported-components` and skips any
   component whose purl type isn't listed. Duplicate purls are scanned
   once.
4. Calls `security scan --purl <purl>` per component, up to
   `--concurrency` at a time (`security.Scan`). The plugin returns
   CycloneDX vulnerabilities, each with `affects` set by the plugin: to
   the purl itself, or, for something it had to unpack (an image), to
   the affected pieces, which it also returns as components.
5. Writes each result as its own CycloneDX document
   (`security.NewReport`) to `vulnerabilities/<purlHash>.json`,
   replacing the previous one. Its `metadata.component` is the scanned
   component (`bom-ref` = purl), its `components` are the unpacked
   pieces some `affects` names, its `vulnerabilities` are exactly what
   the plugin reported, and `metadata.timestamp`/`tools` record when and
   what scanned it.

Nothing in a report depends on the package it was scanned through,
which is why packages sharing a purl share a report.

`bomify package vulnerabilities <tag>` prints the reports of a package's
components (or `--purl` ones) as one JSON array on stdout, in SBOM
order, reading each report as raw JSON so values are never re-encoded.
Components without a report are skipped; warnings go to stderr.

#### Vulnerability gating

`security.Gate` (`internal/security/gate.go`) fails a package when any
report has a vulnerability at or above its threshold (`info` < `low` <
`medium` < `high` < `critical`) that isn't ignored or exempted by VEX. A
vulnerability's severity is the highest of its `ratings`; unrated,
`none`, or `unknown` never fails.

`bomify security scan` picks the gate (`cmd/scanning.go`, `gateFlags`):

1. `--skip-gate`: nothing fails (warning if a rule would have).
2. `--fail-on`, plus `--ignore`.
3. The most specific `conf/scan.json` rule matching the repository.
   Rules have no ignore list on purpose: a standing exemption belongs in
   a VEX document that says which component and why.
4. Otherwise nothing fails.

VEX adds up rather than overriding: the rule's stored documents, then
`--vex` files.

`security.Scan` returns reports instead of writing them. `security scan`
writes them all before checking the gate, so a failing package's reports
are there to inspect. A failure prints a table of the offending
vulnerabilities to stderr.

##### VEX

`security.LoadVEX` (`internal/security/vex.go`) holds statements in
[go-vex](https://github.com/openvex/go-vex)'s OpenVEX model. go-vex reads
OpenVEX (JSON/YAML, any version) and CSAF. CycloneDX VEX is converted:
`not_affected`/`false_positive` → `not_affected`,
`resolved`/`resolved_with_pedigree` → `fixed`, `exploitable` →
`affected`, `in_triage` → `under_investigation`, with `affects` refs
(bom-refs or BOM-Links) resolved to purls through the document's
components. Only `not_affected` and `fixed` exempt.

A finding is exempted only if every target it affects is. A statement
covers a target when its product is that target or the scanned
component, and, if it names subcomponents, the target is one of them.
So "not affected in the image" clears a finding throughout the image,
while "not affected in openssl" doesn't clear it for zlib. Matching is
go-vex's `Statement.Matches`: a versionless purl matches every version,
qualifiers only matter when the statement gives them, and IDs match
through aliases and report `references` (GHSA ↔ CVE). Where statements
disagree, the last wins: documents in order, OpenVEX statements by
timestamp, with an `analysis` already in the report counting first.

Every exemption is logged with its status, justification, and source.
VEX never changes a report; it only decides what fails.

#### Scanning on pull

`bomify pull`/`load` can scan and gate a package before writing any of
it, the one thing a separate `security scan` after the pull can't do.
They take `--scan <type>`, `--fail-on`, and `--skip-scan` (`scanFlags`);
`--ignore` and `--vex` stay on `security scan`, and pulls rely on a
rule's stored VEX. For each package, `pullScanHook` resolves:

1. `--skip-scan`: nothing (warning if a rule would have scanned).
2. The scanner: `--scan`, else the matching rule's, but only if the rule
   lists `pull` in `on` (`security.Rule.AppliesOn`).
3. The gate, as for `security scan`, under the same condition.

A scan on pull is only a gate, so scanner and threshold must come
together. The package is always scanned fresh, never judged by the
reports its publisher attached. For the same reason, a rule's `--on
pull` requires `--fail-on`.

The hook runs as `transfer.Options.Scan`: `pull.PullLayers` hands it the
SBOM after verifying the package and before writing anything, so a
failure leaves nothing behind. The fresh reports are written after the
package's own, replacing them. Scanning may need network access, which
is why nothing scans on pull unless asked.

![Scanning on pull](docs/diagrams/scanning.svg)

*Source: [`docs/diagrams/scanning.mmd`](docs/diagrams/scanning.mmd)*

#### Reports in a registry

Reports travel as an **OCI referrer** of the package manifest, not
inside it (`security.Attach`, called by `push.Push` after packing and
before tagging). Reports go stale and get refreshed; keeping them out of
the manifest means re-scanning never changes the package digest or
orphans its signature.

- **Attach**: one referrer (artifact type
  `application/vnd.bomify.vulnerabilities.v1+json`, annotated
  `land.bomify.scan.plugin`) with one layer per report (media type
  `application/vnd.bomify.component.vulnerabilities.v1+json`, annotated
  with its purl, in SBOM order). It's dated by the newest report's scan
  time, not the push time, so pushing again without re-scanning
  reproduces it byte for byte. With `--sign` it's signed like the
  package.
- **Restore**: after restoring the package, `pull` takes the newest
  report referrer (`security.Referrers`), checks it with the same
  `transfer.Verifier` as the package, and writes its reports to
  `vulnerabilities/`. Reports are advisory: any failure only skips them
  (`Result.ReportsSkipped`, plus a warning).
- **Prune**: after attaching, `push` deletes all but the newest
  `--keep-reports` (default 1; 0 keeps all) report referrers
  (`security.PruneReferrers`), each after whatever refers to it (its
  signature), so no signature is orphaned. Nothing else is touched.
  Deletion is best-effort: registries that refuse `DELETE` (ghcr.io:
  405) only cause a warning, since `pull` always takes the newest.
  `bomify security prune` runs the same pruning on its own and fails
  instead. A `save` tarball is built fresh, so it never needs pruning.

### Signing & verification

A package is signed as a whole: the signature covers its OCI manifest,
which pins the SBOM and every layer by digest, and `pull` verifies each
blob against those digests. The report referrer is signed and verified
the same way, separately. Signatures never go in the SBOM, whose hash is
the build's identity.

[`internal/signature`](internal/signature) implements
`transfer.Options.Sign` and `Verify`, so `save`/`load` get both for free.

- **Sign** (`push`/`save --sign <kind>`): after packing and before
  tagging, bomify writes the payload (the manifest's `mediaType`,
  `digest`, and `size` as JSON), runs the plugin's `signature sign`, and
  pushes the envelope as an OCI 1.1 referrer of the plugin's artifact
  type. A failed sign never leaves a tag on an unsigned package. The
  payload omits `artifactType`, which registries don't return when
  resolving a tag, so it's identical at pull time. On registries without
  the Referrers API (ghcr.io), bomify sets `SkipReferrersGC`, so the
  superseded tag-schema index is left untagged rather than deleted,
  which those registries refuse.
- **Verify** (`pull`/`load`): before fetching anything,
  `signature.Policy` picks the plugin that must verify the reference:
  `--verify` (with only its own `--verify-option`s), else the most
  specific `conf/trust.json` rule, else none. `--insecure-skip-verify`
  overrides a rule, with a warning. Key options are resolved to
  `option=<stored copy path>` as rules are read
  (`signature.ReadResolved`). bomify lists the manifest's referrers,
  keeps those whose artifact type the plugin's `signature
  supported-types` lists, and asks `signature verify` about each until
  one passes. If none does, the pull fails with nothing written.
  Everything afterwards is fetched by that verified descriptor.

![Signing flow](docs/diagrams/signing.svg)

*Source: [`docs/diagrams/signing.mmd`](docs/diagrams/signing.mmd)*

![Verification flow](docs/diagrams/verification.svg)

*Source: [`docs/diagrams/verification.mmd`](docs/diagrams/verification.mmd)*

Plugins never talk to a registry; bomify moves every envelope itself,
which is why one plugin works for registries and tarballs alike.

### Plugin installation

Plugins are distributed as bomify packages whose SBOM lists the binaries
as `bomify-plugin` components (`plugin.PurlType`), one per platform:
`pkg:bomify-plugin/oci@v1.2.0?os=linux&arch=amd64`, with `os`/`arch` in
`GOOS`/`GOARCH` terms (`plugin.Binary`). bomify handles this purl type
itself:

- **Publishing** (`bomify build`): `plugin.PullBinary` copies the binary
  from the component's `distribution` external reference (a local path or
  `file://` URL, relative to the SBOM) into its layer directory. It
  shares `plugin.Pull`'s bookkeeping, so reuse, concurrency, and hash
  verification behave the same; `--check` (`plugin.CheckBinary`) only
  hashes the source.
- **Installing** (`bomify plugin install <name>`,
  [`internal/plugin/install`](internal/plugin/install)): pulls
  `<registry>/<name>:<version>` (`--registry` defaults to
  `ghcr.io/alejandro-velasco/bomify/plugins`) into a staging directory
  inside `plugins/`, never recording it as a local package.
  `pull.PullLayers` downloads only this machine's OS/arch binaries.
  Each binary is checked against its declared SHA-256, and only once all
  pass are they renamed into `plugins/` and recorded in
  `installed.json`. Any failure installs nothing.

Verification (`pluginInstallPolicy`, [`cmd/plugin.go`](cmd/plugin.go))
fails closed: a package installs only if its signature verifies, against
`--verify-option` (always with `bomify-plugin-sigstore`) or the matching
trust rule, or if it's named by digest (`<name>@sha256:...`). bomify has
no built-in signer; users trust the release workflow's identity through
a trust rule, and bootstrap `bomify-plugin-sigstore` itself by digest.
Every binary must also declare a SHA-256. `--verify=false` drops the
signature requirement only; a mismatched checksum still fails. `bomify
plugin list` shows every installed binary and its `installed.json`
entry.

#### Releases

`make plugin-packages` ([`hack/pluginpackages`](hack/pluginpackages))
cross-compiles each first-party plugin and writes its SBOM (plus a
`docker` alias in `oci`'s). `make push-plugin-packages`
([`hack/push-plugin-packages.sh`](hack/push-plugin-packages.sh)) pushes
each as `<registry>/<kind>:<version>` and `:latest`, signed, and writes
the pinned references to `plugin-digests.txt`.

[`release.yml`](.github/workflows/release.yml) runs only after Build
passes on `main`, in three jobs so that only one can sign and that one
runs no npm code:

- `release`: semantic-release ([`.releaserc.json`](.releaserc.json))
  tags, publishes the GitHub release, and pushes the image. It has no
  `id-token` permission.
- `sign-plugins`: builds and pushes the plugin packages with
  `PLUGIN_SIGN_KEYLESS=true`, the only job with `id-token: write`.
  Before each push it fetches a fresh GitHub OIDC token (they expire in
  minutes) and passes it to `bomify-plugin-sigstore` as
  `SIGSTORE_ID_TOKEN`. Fulcio issues a certificate for
  `https://github.com/alejandro-velasco/bomify/.github/workflows/release.yml@refs/heads/main`,
  logged in Rekor. There's no key to store or leak.
- `publish-digests`: attaches `plugin-digests.txt` to the release.

Actions are pinned to commit SHAs and npm packages to exact versions.
Changing `release.yml`, `hack/`, the `Makefile`, or the sigstore plugin
on `main` controls what that signature vouches for, so
[CODEOWNERS](.github/CODEOWNERS) requires the owner's review for them.

### Concurrent, idempotent pulls

`plugin.Pull` is safe to call concurrently, even across processes, for
components sharing a purl hash:

- `manifests/<purlHash>.pid` holds the PID of the process pulling it. A
  second caller waits until the file is gone or its process is dead.
- A stale pid file (process gone) is discarded and the pull redone.
- If a manifest exists and nothing is pulling, the result is reused. A
  reused or fresh result is always checked against the SBOM's declared
  hash, so a same-purl component with a different hash never slips
  through.

## Build & tagging

`bomify build` pulls every component, then records the SBOM as the
build's manifest (`build.RecordManifest`; building the same SBOM again
is a no-op) and points any `--tag`s at its hash
(`build.UpdateRepositories`). `bomify tag` points a new tag at what an
existing one resolves to. `repositories.json` follows Docker's layout,
and a tag without `:version` means `latest`.

### Pruning

`bomify package prune` (and `package remove`, which prunes after
untagging) mirrors `docker image prune`. Every tag keeps its SBOM
manifest and the purl hash of every component it describes; anything
else under `manifests/`, `layers/`, and `vulnerabilities/` is removed,
except items with a live `.pid` file, which are reported as skipped.

A tagged manifest that exists but won't parse is different from a
missing one: its components exist but can't be identified, so they
would be deleted as unreachable. `Prune` reports such manifests in
`PruneResult.Unprotected` instead, and both commands warn about them.

![Pruning reachability walk](docs/diagrams/prune.svg)

*Source: [`docs/diagrams/prune.mmd`](docs/diagrams/prune.mmd)*

## Push & pull (OCI registry)

[`internal/oci/push`](internal/oci/push) and
[`internal/oci/pull`](internal/oci/pull) store a package as an ordinary
OCI artifact (artifact type `application/vnd.bomify.package.v1+json`):

![Bomify package to OCI artifact mapping](docs/diagrams/oci-artifact.svg)

*Source: [`docs/diagrams/oci-artifact.mmd`](docs/diagrams/oci-artifact.mmd)*

- The **config** is the SBOM (`application/vnd.cyclonedx+json` or
  `+xml`, sniffed).
- Each **layer** is a tar of a component's layer directory, annotated
  `land.bomify.purl`. `transfer.WriteTar` zeroes mtimes and uid/gid, so
  the digest depends only on names, modes, and content; otherwise
  re-pushing a component bomify had pulled would re-upload it.
- **Signatures** and the **report referrer** are OCI referrers, so
  neither changes the package digest.

![Package layout in a registry](docs/diagrams/registry-layout.svg)

*Source: [`docs/diagrams/registry-layout.mmd`](docs/diagrams/registry-layout.mmd)*

![Signature referrers in a registry](docs/diagrams/registry-signatures.svg)

*Source: [`docs/diagrams/registry-signatures.mmd`](docs/diagrams/registry-signatures.mmd)*

Layers transfer concurrently (`--concurrency`), each verified against
its digest and size as it streams, with a progress bar per blob. `push`
skips blobs the target already has. That's required, not an
optimization: a local `content/oci.Store` rejects re-pushing a digest,
which `save` hits when tags share a component.

## Save & load

`bomify save`/`load` ([`internal/oci/save`](internal/oci/save)) run
`push`/`pull` unchanged against a local OCI image layout instead of a
registry, then tar or untar it. Shared components are stored once, and
signatures and report referrers travel inside the tarball, so `load`
verifies and restores exactly as `pull` does.

![Save and load flow](docs/diagrams/save-load.svg)

*Source: [`docs/diagrams/save-load.mmd`](docs/diagrams/save-load.mmd)*

## Credentials

[`internal/auth`](internal/auth) is the one source of registry
credentials, for `login`/`logout`, `push`/`pull`, and plugins through
[`pkg/auth`](pkg/auth). It uses Docker's own `~/.docker/config.json` and
native credential store, so `docker login` and `bomify login` are
interchangeable. `Login` verifies a credential before storing it, and
falls back to plaintext (with a warning) only when no credential helper
exists, as `docker login` does.

## Design principles

- **Content-addressing everywhere.** Paths are keyed by SBOM hash, purl
  hash, or digest, so the path is the cache key. That makes builds,
  pulls, and pushes idempotent and safe to run concurrently without a
  lock file or database.
- **Atomic writes.** A final path appears only once its content is
  complete and verified, so a missing path always means "not done yet".
- **bomify orchestrates, plugins do the work.** The core has no
  ecosystem-specific code. Each plugin contract is kept minimal. bomify
  owns everything around it: dispatch, concurrency, caching, reports,
  referrers, and trust policy.
