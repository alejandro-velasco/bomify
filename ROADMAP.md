# bomify Roadmap

Where bomify is going, and what it needs before it can promise stability.

Today bomify builds packages from CycloneDX SBOMs through plugins (oci, helm, generic), moves them with push/pull/save/load/distribute, generates SBOMs for Helm charts, signs and verifies packages (sigstore), attaches SLSA build provenance, and scans them with grype behind a severity gate with VEX exemptions and policy rules. Plugins install from OCI registries.

Status: **done** (on `main`), **in progress** (open branch), or **open** (not started).

## 1. Supply-chain trust

- **Signing and verification** (done, #36, #43): `push`/`save` sign packages, `pull`/`load` verify them, and `bomify trust` rules keep keys in a managed key store.
- **Hash checking on build** (done): a pulled component whose SBOM hash doesn't match fails the build. It's always on, not a `--verify-hashes` flag.
- **Provenance** (done, #49): `build --provenance` records a SLSA v1 predicate, and `push`/`save` attach it as an in-toto attestation, signed with `--sign` through the signing contract's `signature attest`.
- **Provenance verification** (open): bomify doesn't check provenance on `pull`/`load` yet; only external tools (cosign, slsa-verifier, `gh attestation verify`) do. A `--verify-provenance` flag, or a trust rule that requires an attestation from a given builder, would make it more than metadata.

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

bomify is pre-alpha: v2.0.0 through v5.0.0 shipped within four days, and the trust features (signing, VEX, scan gating, provenance) were reshaped across the last several PRs; provenance alone broke the signing contract (#49). The code is not the blocker (tests pass, core packages have 75–90% coverage); the moving interfaces are. These steps, in order, get it to a 1.0 with a compatibility promise.

### Alpha: name the stable surface

- **Define the public surface:** commands and flags, the registry format (config blob, layer and referrer media types, annotations), `save` tarballs, the plugin contracts, and `pkg/`. Everything else is internal and free to change.
- **Version the plugin contracts:** bomify and each plugin declare the contract version they speak, and bomify refuses a mismatch with a clear error.
- **Version the data directory:** record a schema version and migrate, or refuse with instructions, on mismatch.
- **Close out the trust model:** add provenance verification on pull, or decide it stays external, then stop changing the signing contract.

### Beta: prove the surface

- **Feature freeze** on anything that changes the public surface; fixes and plugins only.
- **A second plugin per contract** (e.g. a Trivy scanner, a second signer, a non-Helm SBOM generator), to show the contracts aren't shaped around their first implementation.
- **Registry compatibility tests** against ghcr.io, Docker Hub, Harbor, ECR and a local `registry:2`, run in CI. The ghcr.io referrers fix (#38) shows registry differences still surface late.
- **Raise coverage where it's thin:** `internal/oci/transfer`, `pkg/plugin` (the library third-party plugins build on), and the helm plugin's command layer.
- **Back-compat tests:** packages and tarballs written by the first beta must still pull and load.

### 1.0: promise it

- **A quiet period** of several weeks with no breaking release.
- **A written compatibility policy:** what semver covers, how long older contract versions and data directories stay supported, and how deprecations are announced.
- **Drop the pre-alpha warning** from the README and the docs site.

## Where to start

1. **Plugin contract and data directory versioning**, since every later change depends on them.
2. **Decide on provenance verification**, then freeze the trust model.
3. **A Trivy plugin and registry compatibility tests**, to prove the contracts and the registry format.
4. **`diff` and incremental save**, once the surface is stable, to sharpen the offline-delivery story.
