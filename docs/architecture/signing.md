# Signing and verification

A package is signed as a whole: the signature covers its OCI manifest,
which pins the SBOM and every layer by digest, and `pull` verifies each
blob against those digests. The report referrer is signed and verified
the same way, separately. Signatures never go in the SBOM, whose hash is
the build's identity.

[`internal/signature`](https://github.com/alejandro-velasco/bomify/tree/main/internal/signature) implements
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

![Signing flow](../diagrams/signing.svg)

*Source: [`docs/diagrams/signing.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/signing.mmd)*

![Verification flow](../diagrams/verification.svg)

*Source: [`docs/diagrams/verification.mmd`](https://github.com/alejandro-velasco/bomify/blob/main/docs/diagrams/verification.mmd)*

Plugins never talk to a registry; bomify moves every envelope itself,
which is why one plugin works for registries and tarballs alike.
