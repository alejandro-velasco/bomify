# bomify Roadmap

Where bomify is going, and what it needs before it can promise stability.

Today bomify builds packages from CycloneDX SBOMs through plugins (oci, helm, generic), moves them with push/pull/save/load/distribute, generates SBOMs for Helm charts, signs and verifies packages (sigstore), attaches SLSA build provenance, and scans them with grype behind a severity gate with VEX exemptions and policy rules. Plugins install from OCI registries.

Status: **done** (on `main`), **in progress** (open branch), or **open** (not started).

## 1. Supply-chain trust

- **Signing and verification** (done, #36, #43): `push`/`save` sign packages, `pull`/`load` verify them, and `bomify trust` rules keep keys in a managed key store.
- **Hash checking on build** (done): a pulled component whose SBOM hash doesn't match fails the build. It's always on, not a `--verify-hashes` flag.
- **Provenance** (done, #49): `build --provenance` records a SLSA v1 predicate, and `push`/`save` attach it as an in-toto attestation, signed with `--sign` through the signing contract's `signature attest`.
- **Provenance verification** (open): bomify doesn't check provenance on `pull`/`load` yet; only external tools (cosign, slsa-verifier, `gh attestation verify`) do. A `--verify-provenance` flag, or a trust rule that requires an attestation from a given builder, would make it more than metadata. Decided in [Milestone 2](#milestone-2-trust-model-frozen-100-alpha2).

## 2. Offline (air-gapped) delivery

`save`/`load` plus `distribute`, which already rewrites paths to point at mirrors, cover most of this.

- **Incremental tarballs** (open): `save --since <tag>` ships only the components that changed.
- **`bomify diff <tagA> <tagB>`** (open): show components added, removed or changed, and how vulnerabilities changed between the two.
- **Rewritten SBOM after `distribute`** (open): output an SBOM that points at the internal mirror.

## 3. Deeper security

- **VEX support** (done, #41, #42): VEX documents exempt vulnerabilities from a gate. `push`/`save --vex` publish them with a package, and verified pulls honor them (#46).
- **CI gate** (done, #40, #44): `security scan --fail-on` and `bomify security policy` rules, which also gate `pull` and `load` before anything is written.
- **Scan a built package by tag** (done, #34, #39): reports are stored as OCI referrers.
- **More scanners** (open): Trivy and OSV-Scanner plugins.

## 4. More ecosystems through plugins

- **Component plugins** (open): npm, PyPI, Maven, Go modules, git, deb/rpm, S3 and Artifactory.
- **SBOM generation** (open): OCI images (via syft), Kustomize, Docker Compose and Terraform modules.
- **License compliance** (open): as a new plugin class or a built-in command.

## 5. Product and UX

- **Plugin management** (done, #37): `bomify plugin install/list`, with plugins distributed through OCI registries.
- **Ready-made CI pipeline** (open): a GitHub Action for generate → scan → build → sign → push.
- **SPDX conversion** (open): read and write SPDX as well as CycloneDX.
- **Deploying from packages** (open): a Kubernetes operator or Flux/Argo integration.

## Path to stability

bomify is pre-alpha: v2.0.0 through v5.0.0 shipped within four days, and the trust features (signing, VEX, scan gating, provenance) were reshaped across the last several PRs; provenance alone broke the signing contract (#49). The code is not the blocker (tests pass, and core packages have 75–90% coverage); the moving interfaces are. These milestones get it to a beta, then a 1.0 with a compatibility promise.

Releases follow the prerelease branches from #50: `alpha-release` cuts `1.0.0-alpha.N`, `beta-release` cuts `1.0.0-beta.N`, and `main` cuts 1.0.0 once it joins the release trigger. The beta goals are a stable trust model, versioned plugin contracts, a versioned data directory, and test coverage in `internal/oci/transfer`. Each milestone below lists its exit criteria.

### Milestone 1: versioning foundations (`1.0.0-alpha.1`)

Versioning goes first, so every later change to a contract or the layout can be made safely instead of silently breaking things.

- **Data directory version:** bomify records a schema version in the data directory (e.g. `<data-dir>/version.json`), set on first use and checked on every command in `internal/layout`.
  - A newer version than bomify knows: refuse with an error naming the version.
  - An older version: migrate in place, atomically, with a test per step.
  - A non-empty directory with no version (pre-alpha): refuse with instructions to reset it, since nothing promised it would carry over.
- **What the version covers:** the layout and the schemas of the files bomify reads back: `conf/*.json`, `package/repositories.json`, the `keys/` and `vex/` `index.json` files, and the manifest and provenance records. Changing any of these bumps the version.
- **Plugin contract versions:** each contract (component, SBOM, security, signing) gets a major version, starting at 1.
  - Every plugin reports the versions it speaks through a command `pkg/plugin` adds automatically (e.g. `bomify-plugin-<kind> contract`, printing JSON).
  - bomify checks it before the first call and refuses a mismatch with an error naming both versions.
  - `bomify plugin install` checks it too, from an annotation on the plugin package, before writing anything.
- **Contract change policy,** stated in `plugins/README.md`:
  - adding an optional flag or result field is a minor change, which old plugins and old bomify both ignore;
  - removing or renaming anything, or changing what it means, is a major change and gets a new version.

**Exit:** `1.0.0-alpha.1` refuses a data directory or plugin it can't handle, and says why, instead of misbehaving.

### Milestone 2: trust model frozen (`1.0.0-alpha.2`)

The trust model changed in nearly every recent PR (#36, #39–#46, #49); this milestone makes those changes the last ones.

- **Provenance verification:** decide whether bomify checks provenance itself.
  - If it does: a trust rule option requiring a verified attestation from a given builder on `pull`/`load`, refusing the package before anything is written, like signature verification.
  - If it doesn't: say in the docs that verification is left to external tools.
- **Freeze the signing contract at v1:** `signature sign`, `attest`, `verify`, and `supported-types`, with the in-toto payload type fixed.
- **Document the registry format as public:** the package manifest and config blob, plus the referrer artifact types and annotations for signatures, attestations, VEX documents, and vulnerability reports. These are what other tools and older bomify releases rely on.
- **Freeze the rule schemas:** `trust.json` and `scan.json`, under the data directory version from Milestone 1.
- **Write down the trust guarantees** in `docs/architecture/`. Examples: what `--verify` protects against, why push access alone can't silence findings, and which referrers a pull trusts and when.

**Exit:** no open change to signing, verification, VEX, scan gating, or provenance would break the signing contract, the registry format, or the rule schemas.

### Milestone 3: beta (`1.0.0-beta.1`)

- **Coverage in `internal/oci/transfer` from 75% to at least 90%,** starting with the paths that guard untrusted input:
  - `IsSafeFilename` (0% today): table tests for `..`, absolute paths, and odd separators, plus a fuzz test.
  - `ExtractTar` (71%): path traversal, symlinks and hard links, and truncated or corrupt archives.
  - `FetchAttachment`, `ReferrerLayers`, and `Referrers`: their error paths and the tag-schema fallback.
  - `WithDefaults` and `Label`: what's left.
- **A CI coverage floor** for `internal/oci/transfer`, so the package can't drop back below 90%.
- **Back-compat fixtures:** commit a data directory, a pushed package, and a `save` tarball made by `1.0.0-alpha.2`. Test that the beta migrates the data directory, pulls the package, and loads the tarball.
- **Feature freeze:** once `beta-release` is cut, it takes only fixes and changes that don't touch the public surface. A breaking change must go through a new contract version or a data directory migration.

**Exit:** `1.0.0-beta.1` is cut from `beta-release` with every item above done. Later betas don't break plugin contract v1, the registry format, or data directory v1 without a migration.

### After beta

These prove the surface against more than one implementation and more than one registry, before 1.0:

- **A second plugin per contract** (e.g. a Trivy scanner, a second signer, a non-Helm SBOM generator), to show the contracts aren't shaped around their first implementation.
- **Registry compatibility tests** against ghcr.io, Docker Hub, Harbor, ECR and a local `registry:2`, run in CI. The ghcr.io referrers fix (#38) shows registry differences still surface late.
- **Coverage in `pkg/plugin`,** the library third-party plugins build on, and the helm plugin's command layer.

### 1.0: promise it

- **A quiet period** of several weeks with no breaking release.
- **A written compatibility policy:** what semver covers, how long older contract versions and data directories stay supported, and how deprecations are announced.
- **Drop the pre-alpha warning** from the README and the docs site.

## Where to start

1. **Data directory and plugin contract versioning** (Milestone 1), since every later change depends on them.
2. **Decide on provenance verification**, then freeze the signing contract, the registry format, and the rule schemas (Milestone 2).
3. **`internal/oci/transfer` coverage,** starting with `IsSafeFilename` and `ExtractTar`. It doesn't depend on the other two, so it can run alongside them.
4. **`diff` and incremental save**, after beta, to sharpen the offline-delivery story.
