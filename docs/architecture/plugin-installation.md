# Plugin installation

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
  [`internal/plugin/install`](https://github.com/alejandro-velasco/bomify/tree/main/internal/plugin/install)): pulls
  `<registry>/<name>:<version>` (`--registry` defaults to
  `ghcr.io/alejandro-velasco/bomify/plugins`) into a staging directory
  inside `plugins/`, never recording it as a local package.
  `pull.PullLayers` downloads only this machine's OS/arch binaries.
  Each binary is checked against its declared SHA-256, and only once all
  pass are they renamed into `plugins/` and recorded in
  `installed.json`. Any failure installs nothing.

Verification (`pluginInstallPolicy`, [`cmd/plugin.go`](https://github.com/alejandro-velasco/bomify/blob/main/cmd/plugin.go))
fails closed: a package installs only if its signature verifies, against
`--verify-option` (always with `bomify-plugin-sigstore`) or the matching
trust rule, or if it's named by digest (`<name>@sha256:...`). bomify has
no built-in signer; users trust the release workflow's identity through
a trust rule, and bootstrap `bomify-plugin-sigstore` itself by digest.
Every binary must also declare a SHA-256. `--verify=false` drops the
signature requirement only; a mismatched checksum still fails. `bomify
plugin list` shows every installed binary and its `installed.json`
entry.

## Contract versions

bomify refuses a plugin that doesn't speak the
[contract version](https://github.com/alejandro-velasco/bomify/blob/main/plugins/README.md#contract-versions)
it needs, which is `pkg/plugin`'s (`ContractVersions`), both when installing
it and when calling it:

- **Installing**: each binary's component records the versions it
  speaks as the `land.bomify.plugin.contracts` property, e.g.
  `{"component":1}`, which `hack/pluginpackages` gets from the plugin's
  `contract` subcommand at release. `Install` checks it once the binary
  is staged, before its SHA-256, with `plugin.CheckCompatible`: every contract bomify speaks that the binary
  records must be at bomify's version, since bomify can't yet tell which
  one it will be called through. A binary recording none predates
  contract versions and is refused.
- **Calling**: `plugin.Find` takes the contract its caller is about to
  use, and before returning the binary asks it with `contract` and
  checks that contract's version (`plugin.CheckOffered`). Each binary is
  asked once per run, cached by path, size, and modification time. A
  binary that can't answer predates contract versions, so it's refused
  with an upgrade hint, as is one installed some other way that speaks
  the wrong version.

Either error names the plugin, the versions it offers, and the version
bomify needs, and wraps `plugin.ErrIncompatible`. An incompatible
`bomify-plugin-sigstore` can't verify its own replacement, so
`pluginInstallPolicy` then only accepts a package pinned by digest, as
when bootstrapping it; any other failure to find it is an error.

## Releases

`make plugin-packages` ([`hack/pluginpackages`](https://github.com/alejandro-velasco/bomify/tree/main/hack/pluginpackages))
cross-compiles each first-party plugin and writes its SBOM (plus a
`docker` alias in `oci`'s). `make push-plugin-packages`
([`hack/push-plugin-packages.sh`](https://github.com/alejandro-velasco/bomify/blob/main/hack/push-plugin-packages.sh)) pushes
each as `<registry>/<kind>:<version>` and `:latest`, signed, with its
[build provenance](provenance.md) attached and signed the same way, and
writes the pinned references to `plugin-digests.txt`.

[`release.yml`](https://github.com/alejandro-velasco/bomify/blob/main/.github/workflows/release.yml) runs only after Build
passes on a release branch (`alpha-release` or `beta-release`; `main`
joins at the first GA release), in three jobs so that only one can sign and that one
runs no npm code:

- `release`: semantic-release ([`.releaserc.json`](https://github.com/alejandro-velasco/bomify/blob/main/.releaserc.json))
  tags, publishes the GitHub release, and pushes the image. It has no
  `id-token` permission.
- `sign-plugins`: builds and pushes the plugin packages with
  `PLUGIN_SIGN_KEYLESS=true`, the only job with `id-token: write`.
  Before each push it fetches a fresh GitHub OIDC token (they expire in
  minutes) and passes it to `bomify-plugin-sigstore` as
  `SIGSTORE_ID_TOKEN`, and sets `BOMIFY_INVOCATION_ID` to the run's
  URL. Fulcio issues a certificate for
  `https://github.com/alejandro-velasco/bomify/.github/workflows/release.yml@refs/heads/main`,
  logged in Rekor. There's no key to store or leak.
- `publish-digests`: attaches `plugin-digests.txt` to the release.

Actions are pinned to commit SHAs and npm packages to exact versions.
Changing `release.yml`, `hack/`, the `Makefile`, or the sigstore plugin
on `main` controls what that signature vouches for, so
[CODEOWNERS](https://github.com/alejandro-velasco/bomify/blob/main/.github/CODEOWNERS) requires the owner's review for them.
